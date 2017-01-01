/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Write.h"
#include "ipc/Inquirer.h"
#include "ipc/Port.h"
#include "ipc/TypedMsgHdr.h"
#include "MemBuf.h"
#include <algorithm>

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Inquirer);

Ipc::Inquirer::RequestsMap Ipc::Inquirer::TheRequestsMap;
unsigned int Ipc::Inquirer::LastRequestId = 0;

/// compare Ipc::StrandCoord using kidId, for std::sort() below
static bool
LesserStrandByKidId(const Ipc::StrandCoord &c1, const Ipc::StrandCoord &c2)
{
    return c1.kidId < c2.kidId;
}

Ipc::Inquirer::Inquirer(Request::Pointer aRequest, const StrandCoords& coords,
                        double aTimeout):
    AsyncJob("Ipc::Inquirer"),
    request(aRequest), strands(coords), pos(strands.begin()), timeout(aTimeout)
{
    debugs(54, 5, HERE);

    // order by ascending kid IDs; useful for non-aggregatable stats
    std::sort(strands.begin(), strands.end(), LesserStrandByKidId);
}

Ipc::Inquirer::~Inquirer()
{
    debugs(54, 5, HERE);
    cleanup();
}

void
Ipc::Inquirer::cleanup()
{
}

void
Ipc::Inquirer::start()
{
    request->requestId = 0;
}

void
Ipc::Inquirer::inquire()
{
    if (pos == strands.end()) {
        Must(done());
        return;
    }

    Must(request->requestId == 0);
    AsyncCall::Pointer callback = asyncCall(54, 5, "Mgr::Inquirer::handleRemoteAck",
                                            HandleAckDialer(this, &Inquirer::handleRemoteAck, NULL));
    if (++LastRequestId == 0) // don't use zero value as request->requestId
        ++LastRequestId;
    request->requestId = LastRequestId;
    const int kidId = pos->kidId;
    debugs(54, 4, HERE << "inquire kid: " << kidId << status());
    TheRequestsMap[request->requestId] = callback;
    TypedMsgHdr message;
    request->pack(message);
    SendMessage(Port::MakeAddr(strandAddrLabel, kidId), message);
    eventAdd("Ipc::Inquirer::requestTimedOut", &Inquirer::RequestTimedOut,
             this, timeout, 0, false);
}

/// called when a strand is done writing its output
void
Ipc::Inquirer::handleRemoteAck(Response::Pointer response)
{
    debugs(54, 4, HERE << status());
    request->requestId = 0;
    removeTimeoutEvent();
    if (aggregate(response)) {
        Must(!done()); // or we should not be called
        ++pos; // advance after a successful inquiry
        inquire();
    } else {
        mustStop("error");
    }
}

void
Ipc::Inquirer::swanSong()
{
    debugs(54, 5, HERE);
    removeTimeoutEvent();
    if (request->requestId > 0) {
        DequeueRequest(request->requestId);
        request->requestId = 0;
    }
    sendResponse();
    cleanup();
}

bool
Ipc::Inquirer::doneAll() const
{
    return pos == strands.end();
}

void
Ipc::Inquirer::handleException(const std::exception& e)
{
    debugs(54, 3, HERE << e.what());
    mustStop("exception");
}

void
Ipc::Inquirer::callException(const std::exception& e)
{
    debugs(54, 3, HERE);
    try {
        handleException(e);
    } catch (const std::exception& ex) {
        debugs(54, DBG_CRITICAL, HERE << ex.what());
    }
    AsyncJob::callException(e);
}

/// returns and forgets the right Inquirer callback for strand request
AsyncCall::Pointer
Ipc::Inquirer::DequeueRequest(unsigned int requestId)
{
    debugs(54, 3, HERE << " requestId " << requestId);
    Must(requestId != 0);
    AsyncCall::Pointer call;
    RequestsMap::iterator request = TheRequestsMap.find(requestId);
    if (request != TheRequestsMap.end()) {
        call = request->second;
        Must(call != NULL);
        TheRequestsMap.erase(request);
    }
    return call;
}

void
Ipc::Inquirer::HandleRemoteAck(const Response& response)
{
    Must(response.requestId != 0);
    AsyncCall::Pointer call = DequeueRequest(response.requestId);
    if (call != NULL) {
        HandleAckDialer* dialer = dynamic_cast<HandleAckDialer*>(call->getDialer());
        Must(dialer);
        dialer->arg1 = response.clone();
        ScheduleCallHere(call);
    }
}

/// called when we are no longer waiting for the strand to respond
void
Ipc::Inquirer::removeTimeoutEvent()
{
    if (eventFind(&Inquirer::RequestTimedOut, this))
        eventDelete(&Inquirer::RequestTimedOut, this);
}

/// Ipc::Inquirer::requestTimedOut wrapper
void
Ipc::Inquirer::RequestTimedOut(void* param)
{
    debugs(54, 3, HERE);
    Must(param != NULL);
    Inquirer* cmi = static_cast<Inquirer*>(param);
    // use async call to enable job call protection that time events lack
    CallJobHere(54, 5, cmi, Inquirer, requestTimedOut);
}

/// called when the strand failed to respond (or finish responding) in time
void
Ipc::Inquirer::requestTimedOut()
{
    debugs(54, 3, HERE);
    if (request->requestId != 0) {
        DequeueRequest(request->requestId);
        request->requestId = 0;
        Must(!done()); // or we should not be called
        ++pos; // advance after a failed inquiry
        inquire();
    }
}

const char*
Ipc::Inquirer::status() const
{
    static MemBuf buf;
    buf.reset();
    buf.Printf(" [request->requestId %u]", request->requestId);
    buf.terminate();
    return buf.content();
}

