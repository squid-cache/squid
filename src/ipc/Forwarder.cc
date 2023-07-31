/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "errorpage.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ipc/Forwarder.h"
#include "ipc/Port.h"
#include "ipc/RequestId.h"
#include "ipc/TypedMsgHdr.h"

Ipc::Forwarder::RequestsMap Ipc::Forwarder::TheRequestsMap;
Ipc::RequestId::Index Ipc::Forwarder::LastRequestId = 0;

Ipc::Forwarder::Forwarder(Request::Pointer aRequest, double aTimeout):
    AsyncJob("Ipc::Forwarder"),
    codeContext(CodeContext::Current()),
    request(aRequest), timeout(aTimeout)
{
}

Ipc::Forwarder::~Forwarder()
{
    SWALLOW_EXCEPTIONS({
        Must(request->requestId == 0);
    });
}

void
Ipc::Forwarder::start()
{
    debugs(54, 3, MYNAME);

    typedef NullaryMemFunT<Forwarder> Dialer;
    AsyncCall::Pointer callback = JobCallback(54, 5, Dialer, this, Forwarder::handleRemoteAck);
    if (++LastRequestId == 0) // don't use zero value as request->requestId
        ++LastRequestId;
    request->requestId = LastRequestId;
    TheRequestsMap[request->requestId] = callback;
    TypedMsgHdr message;

    try {
        request->pack(message);
    } catch (...) {
        // assume the pack() call failed because the message did not fit
        // TODO: add a more specific exception?
        handleError();
        return;
    }

    SendMessage(Ipc::Port::CoordinatorAddr(), message);
    eventAdd("Ipc::Forwarder::requestTimedOut", &Forwarder::RequestTimedOut,
             this, timeout, 0, false);
}

void
Ipc::Forwarder::swanSong()
{
    debugs(54, 5, MYNAME);
    removeTimeoutEvent();
    if (request->requestId > 0) {
        DequeueRequest(request->requestId);
        request->requestId = 0;
    }
}

bool
Ipc::Forwarder::doneAll() const
{
    debugs(54, 5, MYNAME);
    return request->requestId == 0;
}

/// called when Coordinator starts processing the request
void
Ipc::Forwarder::handleRemoteAck()
{
    debugs(54, 3, MYNAME);
    request->requestId = 0;
    // Do not do entry->complete() because it will trigger our client side
    // processing when we no longer own the client-Squid connection.
    // Let job cleanup close the client-Squid connection that Coordinator
    // now owns.
}

/// Ipc::Forwarder::requestTimedOut wrapper
void
Ipc::Forwarder::RequestTimedOut(void* param)
{
    debugs(54, 3, MYNAME);
    Must(param != nullptr);
    Forwarder* fwdr = static_cast<Forwarder*>(param);
    // use async call to enable job call protection that time events lack

    CallBack(fwdr->codeContext, [&fwdr] {
        CallJobHere(54, 5, fwdr, Forwarder, requestTimedOut);
    });
}

/// called when Coordinator fails to start processing the request [in time]
void
Ipc::Forwarder::requestTimedOut()
{
    debugs(54, 3, MYNAME);
    handleTimeout();
}

void
Ipc::Forwarder::handleError()
{
    mustStop("error");
}

void
Ipc::Forwarder::handleTimeout()
{
    mustStop("timeout");
}

/// terminate with an error
void
Ipc::Forwarder::handleException(const std::exception& e)
{
    debugs(54, 3, e.what());
    mustStop("exception");
}

void
Ipc::Forwarder::callException(const std::exception& e)
{
    try {
        handleException(e);
    } catch (const std::exception& ex) {
        debugs(54, DBG_CRITICAL, ex.what());
    }
    AsyncJob::callException(e);
}

/// returns and forgets the right Forwarder callback for the request
AsyncCall::Pointer
Ipc::Forwarder::DequeueRequest(const RequestId::Index requestId)
{
    debugs(54, 3, MYNAME);
    Must(requestId != 0);
    AsyncCall::Pointer call;
    RequestsMap::iterator request = TheRequestsMap.find(requestId);
    if (request != TheRequestsMap.end()) {
        call = request->second;
        Must(call != nullptr);
        TheRequestsMap.erase(request);
    }
    return call;
}

/// called when we are no longer waiting for Coordinator to respond
void
Ipc::Forwarder::removeTimeoutEvent()
{
    if (eventFind(&Forwarder::RequestTimedOut, this))
        eventDelete(&Forwarder::RequestTimedOut, this);
}

void
Ipc::Forwarder::HandleRemoteAck(const RequestId requestId)
{
    debugs(54, 3, MYNAME);
    Must(requestId != 0);

    AsyncCall::Pointer call = DequeueRequest(requestId);
    if (call != nullptr)
        ScheduleCallHere(call);
}

