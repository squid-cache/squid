/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "CommCalls.h"
#include "errorpage.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ipc/Port.h"
#include "mgr/Forwarder.h"
#include "mgr/Request.h"
#include "SquidTime.h"
#include "Store.h"


CBDATA_NAMESPACED_CLASS_INIT(Mgr, Forwarder);

Mgr::Forwarder::RequestsMap Mgr::Forwarder::TheRequestsMap;
unsigned int Mgr::Forwarder::LastRequestId = 0;

Mgr::Forwarder::Forwarder(int aFd, const ActionParams &aParams,
                          HttpRequest* aRequest, StoreEntry* anEntry):
        AsyncJob("Mgr::Forwarder"),
        params(aParams),
        request(aRequest), entry(anEntry), fd(aFd), requestId(0), closer(NULL)
{
    debugs(16, 5, HERE << "FD " << aFd);
    Must(fd >= 0);
    Must(request != NULL);
    Must(entry != NULL);

    HTTPMSGLOCK(request);
    entry->lock();
    EBIT_SET(entry->flags, ENTRY_FWD_HDR_WAIT);

    closer = asyncCall(16, 5, "Mgr::Forwarder::noteCommClosed",
                       CommCbMemFunT<Forwarder, CommCloseCbParams>(this, &Forwarder::noteCommClosed));
    comm_add_close_handler(fd, closer);
}

Mgr::Forwarder::~Forwarder()
{
    debugs(16, 5, HERE);
    Must(request != NULL);
    Must(entry != NULL);
    Must(requestId == 0);

    HTTPMSGUNLOCK(request);
    entry->unregisterAbort();
    entry->unlock();
    close();
}

/// closes our copy of the client HTTP connection socket
void
Mgr::Forwarder::close()
{
    if (fd >= 0) {
        if (closer != NULL) {
            comm_remove_close_handler(fd, closer);
            closer = NULL;
        }
        comm_close(fd);
        fd = -1;
    }
}

void
Mgr::Forwarder::start()
{
    debugs(16, 3, HERE);
    entry->registerAbort(&Forwarder::Abort, this);

    typedef NullaryMemFunT<Mgr::Forwarder> Dialer;
    AsyncCall::Pointer callback = JobCallback(16, 5, Dialer, this,
                                  Forwarder::handleRemoteAck);
    if (++LastRequestId == 0) // don't use zero value as requestId
        ++LastRequestId;
    requestId = LastRequestId;
    TheRequestsMap[requestId] = callback;
    Request mgrRequest(KidIdentifier, requestId, fd, params);
    Ipc::TypedMsgHdr message;

    try {
        mgrRequest.pack(message);
    } catch (...) {
        // assume the pack() call failed because the message did not fit
        // TODO: add a more specific exception?
        debugs(16, DBG_CRITICAL, "ERROR: uri " << entry->url() << " exceeds buffer size");
        quitOnError("long URI", errorCon(ERR_INVALID_URL, HTTP_REQUEST_URI_TOO_LARGE, request));
    }

    Ipc::SendMessage(Ipc::coordinatorAddr, message);
    const double timeout = 10; // in seconds
    eventAdd("Mgr::Forwarder::requestTimedOut", &Forwarder::RequestTimedOut,
             this, timeout, 0, false);
}

void
Mgr::Forwarder::swanSong()
{
    debugs(16, 5, HERE);
    removeTimeoutEvent();
    if (requestId > 0) {
        DequeueRequest(requestId);
        requestId = 0;
    }
    close();
}

bool
Mgr::Forwarder::doneAll() const
{
    debugs(16, 5, HERE);
    return requestId == 0;
}

/// called when the client socket gets closed by some external force
void
Mgr::Forwarder::noteCommClosed(const CommCloseCbParams &io)
{
    debugs(16, 5, HERE);
    Must(fd == io.fd);
    fd = -1;
    mustStop("commClosed");
}

/// called when Coordinator starts processing the request
void
Mgr::Forwarder::handleRemoteAck()
{
    debugs(16, 3, HERE);
    Must(entry != NULL);

    requestId = 0;
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->complete();
}

/// Mgr::Forwarder::requestTimedOut wrapper
void
Mgr::Forwarder::RequestTimedOut(void* param)
{
    debugs(16, 3, HERE);
    Must(param != NULL);
    Forwarder* mgrFwdr = static_cast<Forwarder*>(param);
    // use async call to enable job call protection that time events lack
    CallJobHere(16, 5, mgrFwdr, Mgr::Forwarder, requestTimedOut);
}

/// called when Coordinator fails to start processing the request [in time]
void
Mgr::Forwarder::requestTimedOut()
{
    debugs(16, 3, HERE);
    quitOnError("timeout", errorCon(ERR_LIFETIME_EXP, HTTP_REQUEST_TIMEOUT, request));
}

/// terminate with an error
void
Mgr::Forwarder::quitOnError(const char *reason, ErrorState *error)
{
    debugs(16, 3, HERE);
    Must(reason != NULL);
    Must(error != NULL);
    Must(entry != NULL);
    Must(request != NULL);

    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->buffer();
    entry->replaceHttpReply(error->BuildHttpReply());
    entry->expires = squid_curtime;
    errorStateFree(error);
    entry->flush();
    entry->complete();

    mustStop(reason);
}

void
Mgr::Forwarder::callException(const std::exception& e)
{
    try {
        if (entry != NULL && request != NULL && fd >= 0)
            quitOnError("exception", errorCon(ERR_INVALID_RESP, HTTP_INTERNAL_SERVER_ERROR, request));
    } catch (const std::exception& ex) {
        debugs(16, DBG_CRITICAL, HERE << ex.what());
    }
    AsyncJob::callException(e);
}

/// returns and forgets the right Forwarder callback for the request
AsyncCall::Pointer
Mgr::Forwarder::DequeueRequest(unsigned int requestId)
{
    debugs(16, 3, HERE);
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
Mgr::Forwarder::removeTimeoutEvent()
{
    if (eventFind(&Forwarder::RequestTimedOut, this))
        eventDelete(&Forwarder::RequestTimedOut, this);
}

void
Mgr::Forwarder::HandleRemoteAck(unsigned int requestId)
{
    debugs(16, 3, HERE);
    Must(requestId != 0);

    AsyncCall::Pointer call = DequeueRequest(requestId);
    if (call != NULL)
        ScheduleCallHere(call);
}

/// called when something goes wrong with the Store entry
void
Mgr::Forwarder::Abort(void* param)
{
    Forwarder* mgrFwdr = static_cast<Forwarder*>(param);
    if (mgrFwdr->fd >= 0)
        comm_close(mgrFwdr->fd);
}
