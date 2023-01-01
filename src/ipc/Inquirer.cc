/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "mem/PoolingAllocator.h"
#include "MemBuf.h"

#include <algorithm>
#include <unordered_map>

Ipc::RequestId::Index Ipc::Inquirer::LastRequestId = 0;

namespace Ipc {

/// maps request->id to the Inquirer waiting for the response to that request
using InquirerPointer = CbcPointer<Inquirer>;
using WaitingInquiriesItem = std::pair<const RequestId::Index, InquirerPointer>;
using WaitingInquiries = std::unordered_map<
                         RequestId::Index,
                         InquirerPointer,
                         std::hash<RequestId::Index>,
                         std::equal_to<RequestId::Index>,
                         PoolingAllocator<WaitingInquiriesItem> >;

/// pending Inquirer requests for this process
static WaitingInquiries TheWaitingInquirers;

/// returns and forgets the Inquirer waiting for the given requests
static InquirerPointer
DequeueRequest(const RequestId::Index requestId)
{
    debugs(54, 3, "requestId " << requestId);
    Assure(requestId != 0);
    const auto request = TheWaitingInquirers.find(requestId);
    if (request != TheWaitingInquirers.end()) {
        const auto inquirer = request->second;
        TheWaitingInquirers.erase(request);
        return inquirer; // may already be gone by now
    }
    return nullptr;
}

} // namespace Ipc

/// compare Ipc::StrandCoord using kidId, for std::sort() below
static bool
LesserStrandByKidId(const Ipc::StrandCoord &c1, const Ipc::StrandCoord &c2)
{
    return c1.kidId < c2.kidId;
}

Ipc::Inquirer::Inquirer(Request::Pointer aRequest, const StrandCoords& coords,
                        double aTimeout):
    AsyncJob("Ipc::Inquirer"),
    codeContext(CodeContext::Current()),
    request(aRequest), strands(coords), pos(strands.begin()), timeout(aTimeout)
{
    debugs(54, 5, MYNAME);

    // order by ascending kid IDs; useful for non-aggregatable stats
    std::sort(strands.begin(), strands.end(), LesserStrandByKidId);
}

Ipc::Inquirer::~Inquirer()
{
    debugs(54, 5, MYNAME);
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
    if (++LastRequestId == 0) // don't use zero value as request->requestId
        ++LastRequestId;
    request->requestId = LastRequestId;
    const int kidId = pos->kidId;
    debugs(54, 4, "inquire kid: " << kidId << status());
    TheWaitingInquirers[request->requestId] = this;
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
    debugs(54, 4, status());
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
    debugs(54, 5, MYNAME);
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
    debugs(54, 3, e.what());
    mustStop("exception");
}

void
Ipc::Inquirer::callException(const std::exception& e)
{
    debugs(54, 3, MYNAME);
    try {
        handleException(e);
    } catch (const std::exception& ex) {
        debugs(54, DBG_CRITICAL, ex.what());
    }
    AsyncJob::callException(e);
}

void
Ipc::Inquirer::HandleRemoteAck(const Response& response)
{
    Must(response.requestId != 0);
    const auto inquirer = DequeueRequest(response.requestId);
    if (inquirer.valid()) {
        CallService(inquirer->codeContext, [&] {
            const auto call = asyncCall(54, 5, "Ipc::Inquirer::handleRemoteAck",
                                        JobMemFun(inquirer, &Inquirer::handleRemoteAck, response.clone()));
            ScheduleCallHere(call);
        });
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
    debugs(54, 3, MYNAME);
    Must(param != nullptr);
    Inquirer* cmi = static_cast<Inquirer*>(param);
    // use async call to enable job call protection that time events lack
    CallBack(cmi->codeContext, [&cmi] {
        CallJobHere(54, 5, cmi, Inquirer, requestTimedOut);
    });
}

/// called when the strand failed to respond (or finish responding) in time
void
Ipc::Inquirer::requestTimedOut()
{
    debugs(54, 3, MYNAME);
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
    buf.appendf(" [requestId %u]", request->requestId.index());
    buf.terminate();
    return buf.content();
}

