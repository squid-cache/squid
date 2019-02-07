/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "CommCalls.h"
#include "errorpage.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "ipc/Port.h"
#include "mgr/Forwarder.h"
#include "mgr/Request.h"
#include "SquidTime.h"
#include "Store.h"

CBDATA_NAMESPACED_CLASS_INIT(Mgr, Forwarder);

Mgr::Forwarder::Forwarder(const Comm::ConnectionPointer &aConn, const ActionParams &aParams,
                          HttpRequest* aRequest, StoreEntry* anEntry):
    Ipc::Forwarder(new Request(KidIdentifier, 0, aConn, aParams), 10),
    httpRequest(aRequest), entry(anEntry), conn(aConn)
{
    debugs(16, 5, HERE << conn);
    Must(Comm::IsConnOpen(conn));
    Must(httpRequest != NULL);
    Must(entry != NULL);

    HTTPMSGLOCK(httpRequest);
    entry->lock("Mgr::Forwarder");

    closer = asyncCall(16, 5, "Mgr::Forwarder::noteCommClosed",
                       CommCbMemFunT<Forwarder, CommCloseCbParams>(this, &Forwarder::noteCommClosed));
    comm_add_close_handler(conn->fd, closer);
}

Mgr::Forwarder::~Forwarder()
{
    SWALLOW_EXCEPTIONS({
        Must(entry);
        entry->unlock("Mgr::Forwarder");
        Must(httpRequest);
        HTTPMSGUNLOCK(httpRequest);
    });
}

/// closes our copy of the client HTTP connection socket
void
Mgr::Forwarder::swanSong()
{
    if (Comm::IsConnOpen(conn)) {
        if (closer != NULL) {
            comm_remove_close_handler(conn->fd, closer);
            closer = NULL;
        }
        conn->close();
    }
    conn = NULL;
    Ipc::Forwarder::swanSong();
}

void
Mgr::Forwarder::handleError()
{
    debugs(16, DBG_CRITICAL, "ERROR: uri " << entry->url() << " exceeds buffer size");
    sendError(new ErrorState(ERR_INVALID_URL, Http::scUriTooLong, httpRequest));
    mustStop("long URI");
}

void
Mgr::Forwarder::handleTimeout()
{
    sendError(new ErrorState(ERR_LIFETIME_EXP, Http::scRequestTimeout, httpRequest));
    Ipc::Forwarder::handleTimeout();
}

void
Mgr::Forwarder::handleException(const std::exception &e)
{
    if (entry != NULL && httpRequest != NULL && Comm::IsConnOpen(conn))
        sendError(new ErrorState(ERR_INVALID_RESP, Http::scInternalServerError, httpRequest));
    Ipc::Forwarder::handleException(e);
}

/// called when the client socket gets closed by some external force
void
Mgr::Forwarder::noteCommClosed(const CommCloseCbParams &)
{
    debugs(16, 5, HERE);
    conn = NULL; // needed?
    mustStop("commClosed");
}

/// send error page
void
Mgr::Forwarder::sendError(ErrorState *error)
{
    debugs(16, 3, HERE);
    Must(error != NULL);
    Must(entry != NULL);
    Must(httpRequest != NULL);

    entry->buffer();
    entry->replaceHttpReply(error->BuildHttpReply());
    entry->expires = squid_curtime;
    delete error;
    entry->flush();
    entry->complete();
}

