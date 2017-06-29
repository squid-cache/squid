/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
#include "ipc/TypedMsgHdr.h"

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Forwarder);

Ipc::Forwarder::RequestsMap Ipc::Forwarder::TheRequestsMap;
unsigned int Ipc::Forwarder::LastRequestId = 0;

Ipc::Forwarder::Forwarder(Request::Pointer aRequest, double aTimeout):
    AsyncJob("Ipc::Forwarder"),
    request(aRequest), timeout(aTimeout)
{
    debugs(54, 5, HERE);
}

Ipc::Forwarder::~Forwarder()
{
    debugs(54, 5, HERE);
    Must(request->requestId == 0);
    cleanup();
}

/// perform cleanup actions
void
Ipc::Forwarder::cleanup()
{
}

void
Ipc::Forwarder::start()
{
    debugs(54, 3, HERE);

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
    debugs(54, 5, HERE);
    removeTimeoutEvent();
    if (request->requestId > 0) {
        DequeueRequest(request->requestId);
        request->requestId = 0;
    }
    cleanup();
}

bool
Ipc::Forwarder::doneAll() const
{
    debugs(54, 5, HERE);
    return request->requestId == 0;
}

/// called when Coordinator starts processing the request
void
Ipc::Forwarder::handleRemoteAck()
{
    debugs(54, 3, HERE);
    request->requestId = 0;
    // Do not clear ENTRY_FWD_HDR_WAIT or do entry->complete() because
    // it will trigger our client side processing. Let job cleanup close.
}

/// Ipc::Forwarder::requestTimedOut wrapper
void
Ipc::Forwarder::RequestTimedOut(void* param)
{
    debugs(54, 3, HERE);
    Must(param != NULL);
    Forwarder* fwdr = static_cast<Forwarder*>(param);
    // use async call to enable job call protection that time events lack
    CallJobHere(54, 5, fwdr, Forwarder, requestTimedOut);
}

/// called when Coordinator fails to start processing the request [in time]
void
Ipc::Forwarder::requestTimedOut()
{
    debugs(54, 3, HERE);
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
    debugs(54, 3, HERE << e.what());
    mustStop("exception");
}

void
Ipc::Forwarder::callException(const std::exception& e)
{
    try {
        handleException(e);
    } catch (const std::exception& ex) {
        debugs(54, DBG_CRITICAL, HERE << ex.what());
    }
    AsyncJob::callException(e);
}

/// returns and forgets the right Forwarder callback for the request
AsyncCall::Pointer
Ipc::Forwarder::DequeueRequest(unsigned int requestId)
{
    debugs(54, 3, HERE);
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

/// called when we are no longer waiting for Coordinator to respond
void
Ipc::Forwarder::removeTimeoutEvent()
{
    if (eventFind(&Forwarder::RequestTimedOut, this))
        eventDelete(&Forwarder::RequestTimedOut, this);
}

void
Ipc::Forwarder::HandleRemoteAck(unsigned int requestId)
{
    debugs(54, 3, HERE);
    Must(requestId != 0);

    AsyncCall::Pointer call = DequeueRequest(requestId);
    if (call != NULL)
        ScheduleCallHere(call);
}

