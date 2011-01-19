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


Mgr::Forwarder::Forwarder(int aFd, const ActionParams &aParams,
                          HttpRequest* aRequest, StoreEntry* anEntry):
        Ipc::Forwarder(new Request(KidIdentifier, 0, aFd, aParams), 10),
        httpRequest(aRequest), entry(anEntry), fd(aFd)
{
    debugs(16, 5, HERE << "FD " << fd);
    Must(fd >= 0);
    Must(httpRequest != NULL);
    Must(entry != NULL);

    HTTPMSGLOCK(httpRequest);
    entry->lock();
    EBIT_SET(entry->flags, ENTRY_FWD_HDR_WAIT);

    closer = asyncCall(16, 5, "Mgr::Forwarder::noteCommClosed",
                       CommCbMemFunT<Forwarder, CommCloseCbParams>(this, &Forwarder::noteCommClosed));
    comm_add_close_handler(fd, closer);
}

Mgr::Forwarder::~Forwarder()
{
    debugs(16, 5, HERE);
    Must(httpRequest != NULL);
    Must(entry != NULL);

    HTTPMSGUNLOCK(httpRequest);
    entry->unregisterAbort();
    entry->unlock();
    cleanup();
}

/// closes our copy of the client HTTP connection socket
void
Mgr::Forwarder::cleanup()
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
Mgr::Forwarder::handleError()
{
    debugs(16, DBG_CRITICAL, "ERROR: uri " << entry->url() << " exceeds buffer size");
    sendError(errorCon(ERR_INVALID_URL, HTTP_REQUEST_URI_TOO_LARGE, httpRequest));
    mustStop("long URI");
}

void
Mgr::Forwarder::handleTimeout()
{
    sendError(errorCon(ERR_LIFETIME_EXP, HTTP_REQUEST_TIMEOUT, httpRequest));
    Ipc::Forwarder::handleTimeout();
}

void
Mgr::Forwarder::handleException(const std::exception& e)
{
    if (entry != NULL && httpRequest != NULL && fd >= 0)
        sendError(errorCon(ERR_INVALID_RESP, HTTP_INTERNAL_SERVER_ERROR, httpRequest));
    Ipc::Forwarder::handleException(e);
}

/// called when the client socket gets closed by some external force
void
Mgr::Forwarder::noteCommClosed(const CommCloseCbParams& params)
{
    debugs(16, 5, HERE);
    Must(fd == params.fd);
    fd = -1;
    mustStop("commClosed");
}

/// called when Coordinator starts processing the request
void
Mgr::Forwarder::handleRemoteAck()
{
    Ipc::Forwarder::handleRemoteAck();

    Must(entry != NULL);
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->complete();
}

/// send error page
void
Mgr::Forwarder::sendError(ErrorState *error)
{
    debugs(16, 3, HERE);
    Must(error != NULL);
    Must(entry != NULL);
    Must(httpRequest != NULL);

    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    entry->buffer();
    entry->replaceHttpReply(error->BuildHttpReply());
    entry->expires = squid_curtime;
    errorStateFree(error);
    entry->flush();
    entry->complete();
}
