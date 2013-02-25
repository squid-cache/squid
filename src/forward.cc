/*
 * DEBUG: section 17    Request Forwarding
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/AclAddress.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "anyp/PortCfg.h"
#include "CachePeer.h"
#include "CacheManager.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Loops.h"
#include "CommCalls.h"
#include "errorpage.h"
#include "event.h"
#include "fd.h"
#include "fde.h"
#include "forward.h"
#include "ftp.h"
#include "globals.h"
#include "gopher.h"
#include "hier_code.h"
#include "http.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "internal.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "StoreClient.h"
#include "urn.h"
#include "whois.h"
#if USE_SSL
#include "ssl/support.h"
#include "ssl/ErrorDetail.h"
#include "ssl/ServerBump.h"
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

static PSC fwdPeerSelectionCompleteWrapper;
static CLCB fwdServerClosedWrapper;
#if USE_SSL
static PF fwdNegotiateSSLWrapper;
#endif
static CNCB fwdConnectDoneWrapper;

static OBJH fwdStats;

#define MAX_FWD_STATS_IDX 9
static int FwdReplyCodes[MAX_FWD_STATS_IDX + 1][HTTP_INVALID_HEADER + 1];

static PconnPool *fwdPconnPool = new PconnPool("server-side");
CBDATA_CLASS_INIT(FwdState);

void
FwdState::abort(void* d)
{
    FwdState* fwd = (FwdState*)d;
    Pointer tmp = fwd; // Grab a temporary pointer to keep the object alive during our scope.

    if (Comm::IsConnOpen(fwd->serverConnection())) {
        comm_remove_close_handler(fwd->serverConnection()->fd, fwdServerClosedWrapper, fwd);
        debugs(17, 3, HERE << "store entry aborted; closing " <<
               fwd->serverConnection());
        fwd->serverConnection()->close();
    } else {
        debugs(17, 7, HERE << "store entry aborted; no connection to close");
    }
    fwd->serverDestinations.clean();
    fwd->self = NULL;
}

/**** PUBLIC INTERFACE ********************************************************/

FwdState::FwdState(const Comm::ConnectionPointer &client, StoreEntry * e, HttpRequest * r, const AccessLogEntryPointer &alp):
        al(alp)
{
    debugs(17, 2, HERE << "Forwarding client request " << client << ", url=" << e->url() );
    entry = e;
    clientConn = client;
    request = HTTPMSGLOCK(r);
    pconnRace = raceImpossible;
    start_t = squid_curtime;
    serverDestinations.reserve(Config.forward_max_tries);
    e->lock();
    EBIT_SET(e->flags, ENTRY_FWD_HDR_WAIT);
}

// Called once, right after object creation, when it is safe to set self
void FwdState::start(Pointer aSelf)
{
    // Protect ourselves from being destroyed when the only Server pointing
    // to us is gone (while we expect to talk to more Servers later).
    // Once we set self, we are responsible for clearing it when we do not
    // expect to talk to any servers.
    self = aSelf; // refcounted

    // We hope that either the store entry aborts or peer is selected.
    // Otherwise we are going to leak our object.

    entry->registerAbort(FwdState::abort, this);

#if STRICT_ORIGINAL_DST
    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we must force DIRECT and only to the original client destination.
    const bool isIntercepted = request && !request->flags.redirected && (request->flags.intercepted || request->flags.spoofClientIp);
    const bool useOriginalDst = Config.onoff.client_dst_passthru || (request && !request->flags.hostVerified);
    if (isIntercepted && useOriginalDst) {
        selectPeerForIntercepted();
        // 3.2 does not suppro re-wrapping inside CONNECT.
        // our only alternative is to fake destination "found" and continue with the forwarding.
        startConnectionOrFail();
        return;
    }
#endif

    // do full route options selection
    peerSelect(&serverDestinations, request, entry, fwdPeerSelectionCompleteWrapper, this);
}

#if STRICT_ORIGINAL_DST
/// bypasses peerSelect() when dealing with intercepted requests
void
FwdState::selectPeerForIntercepted()
{
    // use pinned connection if available
    Comm::ConnectionPointer p;
    if (ConnStateData *client = request->pinnedConnection()) {
        p = client->validatePinnedConnection(request, NULL);
        if (Comm::IsConnOpen(p)) {
            /* duplicate peerSelectPinned() effects */
            p->peerType = PINNED;
            entry->ping_status = PING_DONE;     /* Skip ICP */

            debugs(17, 3, "reusing a pinned conn: " << *p);
            serverDestinations.push_back(p);
        } else {
            debugs(17,2, "Pinned connection is not valid: " << p);
            ErrorState *anErr = new ErrorState(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE, request);
            fail(anErr);
        }
        // Either use the valid pinned connection or fail if it is invalid.
        return;
    }

    // use client original destination as second preferred choice
    p = new Comm::Connection();
    p->peerType = ORIGINAL_DST;
    p->remote = clientConn->local;
    getOutgoingAddress(request, p);

    debugs(17, 3, HERE << "using client original destination: " << *p);
    serverDestinations.push_back(p);
}
#endif

void
FwdState::completed()
{
    if (flags.forward_completed == 1) {
        debugs(17, DBG_IMPORTANT, HERE << "FwdState::completed called on a completed request! Bad!");
        return;
    }

    flags.forward_completed = 1;

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        debugs(17, 3, HERE << "entry aborted");
        return ;
    }

#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (entry->store_status == STORE_PENDING) {
        if (entry->isEmpty()) {
            if (!err) // we quit (e.g., fd closed) before an error or content
                fail(new ErrorState(ERR_READ_ERROR, HTTP_BAD_GATEWAY, request));
            assert(err);
            errorAppendEntry(entry, err);
            err = NULL;
#if USE_SSL
            if (request->flags.sslPeek && request->clientConnectionManager.valid()) {
                CallJobHere1(17, 4, request->clientConnectionManager, ConnStateData,
                             ConnStateData::httpsPeeked, Comm::ConnectionPointer(NULL));
            }
#endif
        } else {
            EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
            entry->complete();
            entry->releaseRequest();
        }
    }

    if (storePendingNClients(entry) > 0)
        assert(!EBIT_TEST(entry->flags, ENTRY_FWD_HDR_WAIT));

}

FwdState::~FwdState()
{
    debugs(17, 3, HERE << "FwdState destructor starting");

    if (! flags.forward_completed)
        completed();

    doneWithRetries();

    HTTPMSGUNLOCK(request);

    delete err;

    entry->unregisterAbort();

    entry->unlock();

    entry = NULL;

    if (calls.connector != NULL) {
        calls.connector->cancel("FwdState destructed");
        calls.connector = NULL;
    }

    if (Comm::IsConnOpen(serverConn)) {
        comm_remove_close_handler(serverConnection()->fd, fwdServerClosedWrapper, this);
        debugs(17, 3, HERE << "closing FD " << serverConnection()->fd);
        serverConn->close();
    }

    serverDestinations.clean();

    debugs(17, 3, HERE << "FwdState destructor done");
}

/**
 * This is the entry point for client-side to start forwarding
 * a transaction.  It is a static method that may or may not
 * allocate a FwdState.
 */
void
FwdState::Start(const Comm::ConnectionPointer &clientConn, StoreEntry *entry, HttpRequest *request, const AccessLogEntryPointer &al)
{
    /** \note
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if ( Config.accessList.miss && !request->client_addr.IsNoAddr() &&
            request->protocol != AnyP::PROTO_INTERNAL && request->protocol != AnyP::PROTO_CACHE_OBJECT) {
        /**
         * Check if this host is allowed to fetch MISSES from us (miss_access).
         * Intentionally replace the src_addr automatically selected by the checklist code
         * we do NOT want the indirect client address to be tested here.
         */
        ACLFilledChecklist ch(Config.accessList.miss, request, NULL);
        ch.src_addr = request->client_addr;
        if (ch.fastCheck() == ACCESS_DENIED) {
            err_type page_id;
            page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName, 1);

            if (page_id == ERR_NONE)
                page_id = ERR_FORWARDING_DENIED;

            ErrorState *anErr = new ErrorState(page_id, HTTP_FORBIDDEN, request);
            errorAppendEntry(entry, anErr);	// frees anErr
            return;
        }
    }

    debugs(17, 3, HERE << "'" << entry->url() << "'");
    /*
     * This seems like an odd place to bind mem_obj and request.
     * Might want to assert that request is NULL at this point
     */
    entry->mem_obj->request = HTTPMSGLOCK(request);
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (shutting_down) {
        /* more yuck */
        ErrorState *anErr = new ErrorState(ERR_SHUTTING_DOWN, HTTP_SERVICE_UNAVAILABLE, request);
        errorAppendEntry(entry, anErr);	// frees anErr
        return;
    }

    switch (request->protocol) {

    case AnyP::PROTO_INTERNAL:
        internalStart(clientConn, request, entry);
        return;

    case AnyP::PROTO_CACHE_OBJECT:
        CacheManager::GetInstance()->Start(clientConn, request, entry);
        return;

    case AnyP::PROTO_URN:
        urnStart(request, entry);
        return;

    default:
        FwdState::Pointer fwd = new FwdState(clientConn, entry, request, al);
        fwd->start(fwd);
        return;
    }

    /* NOTREACHED */
}

void
FwdState::fwdStart(const Comm::ConnectionPointer &clientConn, StoreEntry *entry, HttpRequest *request)
{
    // Hides AccessLogEntry.h from code that does not supply ALE anyway.
    Start(clientConn, entry, request, NULL);
}

void
FwdState::startConnectionOrFail()
{
    debugs(17, 3, HERE << entry->url());

    if (serverDestinations.size() > 0) {
        // Ditch error page if it was created before.
        // A new one will be created if there's another problem
        delete err;
        err = NULL;

        // Update the logging information about this new server connection.
        // Done here before anything else so the errors get logged for
        // this server link regardless of what happens when connecting to it.
        // IF sucessfuly connected this top destination will become the serverConnection().
        request->hier.note(serverDestinations[0], request->GetHost());
        request->clearError();

        connectStart();
    } else {
        debugs(17, 3, HERE << "Connection failed: " << entry->url());
        if (!err) {
            ErrorState *anErr = new ErrorState(ERR_CANNOT_FORWARD, HTTP_INTERNAL_SERVER_ERROR, request);
            fail(anErr);
        } // else use actual error from last connection attempt
        self = NULL;       // refcounted
    }
}

void
FwdState::fail(ErrorState * errorState)
{
    debugs(17, 3, HERE << err_type_str[errorState->type] << " \"" << httpStatusString(errorState->httpStatus) << "\"\n\t" << entry->url()  );

    delete err;
    err = errorState;

    if (!errorState->request)
        errorState->request = HTTPMSGLOCK(request);

    if (err->type != ERR_ZERO_SIZE_OBJECT)
        return;

    if (pconnRace == racePossible) {
        debugs(17, 5, HERE << "pconn race happened");
        pconnRace = raceHappened;
    }

    if (ConnStateData *pinned_connection = request->pinnedConnection()) {
        pinned_connection->pinning.zeroReply = true;
        flags.dont_retry = true; // we want to propagate failure to the client
        debugs(17, 4, "zero reply on pinned connection");
    }
}

/**
 * Frees fwdState without closing FD or generating an abort
 */
void
FwdState::unregister(Comm::ConnectionPointer &conn)
{
    debugs(17, 3, HERE << entry->url() );
    assert(serverConnection() == conn);
    assert(Comm::IsConnOpen(conn));
    comm_remove_close_handler(conn->fd, fwdServerClosedWrapper, this);
    serverConn = NULL;
}

// Legacy method to be removed in favor of the above as soon as possible
void
FwdState::unregister(int fd)
{
    debugs(17, 3, HERE << entry->url() );
    assert(fd == serverConnection()->fd);
    unregister(serverConn);
}

/**
 * server-side modules call fwdComplete() when they are done
 * downloading an object.  Then, we either 1) re-forward the
 * request somewhere else if needed, or 2) call storeComplete()
 * to finish it off
 */
void
FwdState::complete()
{
    debugs(17, 3, HERE << entry->url() << "\n\tstatus " << entry->getReply()->sline.status  );
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    logReplyStatus(n_tries, entry->getReply()->sline.status);

    if (reforward()) {
        debugs(17, 3, HERE << "re-forwarding " << entry->getReply()->sline.status << " " << entry->url());

        if (Comm::IsConnOpen(serverConn))
            unregister(serverConn);

        entry->reset();

        // drop the last path off the selection list. try the next one.
        serverDestinations.shift();
        startConnectionOrFail();

    } else {
        if (Comm::IsConnOpen(serverConn))
            debugs(17, 3, HERE << "server FD " << serverConnection()->fd << " not re-forwarding status " << entry->getReply()->sline.status);
        else
            debugs(17, 3, HERE << "server (FD closed) not re-forwarding status " << entry->getReply()->sline.status);
        EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
        entry->complete();

        if (!Comm::IsConnOpen(serverConn))
            completed();

        self = NULL; // refcounted
    }
}

/**** CALLBACK WRAPPERS ************************************************************/

static void
fwdPeerSelectionCompleteWrapper(Comm::ConnectionList * unused, ErrorState *err, void *data)
{
    FwdState *fwd = (FwdState *) data;
    if (err)
        fwd->fail(err);
    fwd->startConnectionOrFail();
}

static void
fwdServerClosedWrapper(const CommCloseCbParams &params)
{
    FwdState *fwd = (FwdState *)params.data;
    fwd->serverClosed(params.fd);
}

#if USE_SSL
static void
fwdNegotiateSSLWrapper(int fd, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->negotiateSSL(fd);
}

#endif

void
fwdConnectDoneWrapper(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->connectDone(conn, status, xerrno);
}

/**** PRIVATE *****************************************************************/

/*
 * FwdState::checkRetry
 *
 * Return TRUE if the request SHOULD be retried.  This method is
 * called when the HTTP connection fails, or when the connection
 * is closed before server-side read the end of HTTP headers.
 */
bool
FwdState::checkRetry()
{
    if (shutting_down)
        return false;

    if (!self) { // we have aborted before the server called us back
        debugs(17, 5, HERE << "not retrying because of earlier abort");
        // we will be destroyed when the server clears its Pointer to us
        return false;
    }

    if (entry->store_status != STORE_PENDING)
        return false;

    if (!entry->isEmpty())
        return false;

    if (n_tries > 10)
        return false;

    if (origin_tries > 2)
        return false;

    if (squid_curtime - start_t > Config.Timeout.forward)
        return false;

    if (flags.dont_retry)
        return false;

    if (request->bodyNibbled())
        return false;

    // NP: not yet actually connected anywhere. retry is safe.
    if (!flags.connected_okay)
        return true;

    if (!checkRetriable())
        return false;

    return true;
}

/*
 * FwdState::checkRetriable
 *
 * Return TRUE if this is the kind of request that can be retried
 * after a failure.  If the request is not retriable then we don't
 * want to risk sending it on a persistent connection.  Instead we'll
 * force it to go on a new HTTP connection.
 */
bool
FwdState::checkRetriable()
{
    /* RFC2616 9.1 Safe and Idempotent Methods */
    switch (request->method.id()) {
        /* 9.1.1 Safe Methods */

    case METHOD_GET:

    case METHOD_HEAD:
        /* 9.1.2 Idempotent Methods */

    case METHOD_PUT:

    case METHOD_DELETE:

    case METHOD_OPTIONS:

    case METHOD_TRACE:
        break;

    default:
        return false;
    }

    return true;
}

void
FwdState::serverClosed(int fd)
{
    debugs(17, 2, HERE << "FD " << fd << " " << entry->url());
    retryOrBail();
}

void
FwdState::retryOrBail()
{
    if (checkRetry()) {
        debugs(17, 3, HERE << "re-forwarding (" << n_tries << " tries, " << (squid_curtime - start_t) << " secs)");
        // we should retry the same destination if it failed due to pconn race
        if (pconnRace == raceHappened)
            debugs(17, 4, HERE << "retrying the same destination");
        else
            serverDestinations.shift(); // last one failed. try another.
        startConnectionOrFail();
        return;
    }

    // TODO: should we call completed() here and move doneWithRetries there?
    doneWithRetries();

    if (self != NULL && !err && shutting_down) {
        ErrorState *anErr = new ErrorState(ERR_SHUTTING_DOWN, HTTP_SERVICE_UNAVAILABLE, request);
        errorAppendEntry(entry, anErr);
    }

    self = NULL;	// refcounted
}

// If the Server quits before nibbling at the request body, the body sender
// will not know (so that we can retry). Call this if we will not retry. We
// will notify the sender so that it does not get stuck waiting for space.
void
FwdState::doneWithRetries()
{
    if (request && request->body_pipe != NULL)
        request->body_pipe->expectNoConsumption();
}

// called by the server that failed after calling unregister()
void
FwdState::handleUnregisteredServerEnd()
{
    debugs(17, 2, HERE << "self=" << self << " err=" << err << ' ' << entry->url());
    assert(!Comm::IsConnOpen(serverConn));
    retryOrBail();
}

#if USE_SSL
void
FwdState::negotiateSSL(int fd)
{
    unsigned long ssl_lib_error = SSL_ERROR_NONE;
    SSL *ssl = fd_table[fd].ssl;
    int ret;

    if ((ret = SSL_connect(ssl)) <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
#ifdef EPROTO
        int sysErrNo = EPROTO;
#else
        int sysErrNo = EACCES;
#endif

        switch (ssl_error) {

        case SSL_ERROR_WANT_READ:
            Comm::SetSelect(fd, COMM_SELECT_READ, fwdNegotiateSSLWrapper, this, 0);
            return;

        case SSL_ERROR_WANT_WRITE:
            Comm::SetSelect(fd, COMM_SELECT_WRITE, fwdNegotiateSSLWrapper, this, 0);
            return;

        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL:
            ssl_lib_error = ERR_get_error();
            debugs(81, DBG_IMPORTANT, "fwdNegotiateSSL: Error negotiating SSL connection on FD " << fd <<
                   ": " << ERR_error_string(ssl_lib_error, NULL) << " (" << ssl_error <<
                   "/" << ret << "/" << errno << ")");

            // store/report errno when ssl_error is SSL_ERROR_SYSCALL, ssl_lib_error is 0, and ret is -1
            if (ssl_error == SSL_ERROR_SYSCALL && ret == -1 && ssl_lib_error == 0)
                sysErrNo = errno;

            // falling through to complete error handling

        default:
            // TODO: move into a method before merge
            Ssl::ErrorDetail *errDetails;
            Ssl::ErrorDetail *errFromFailure = (Ssl::ErrorDetail *)SSL_get_ex_data(ssl, ssl_ex_index_ssl_error_detail);
            if (errFromFailure != NULL) {
                // The errFromFailure is attached to the ssl object
                // and will be released when ssl object destroyed.
                // Copy errFromFailure to a new Ssl::ErrorDetail object.
                errDetails = new Ssl::ErrorDetail(*errFromFailure);
            } else {
                // server_cert can be NULL here
                X509 *server_cert = SSL_get_peer_certificate(ssl);
                errDetails = new Ssl::ErrorDetail(SQUID_ERR_SSL_HANDSHAKE, server_cert, NULL);
                X509_free(server_cert);
            }

            if (ssl_lib_error != SSL_ERROR_NONE)
                errDetails->setLibError(ssl_lib_error);

            if (request->clientConnectionManager.valid()) {
                // remember the server certificate from the ErrorDetail object
                if (Ssl::ServerBump *serverBump = request->clientConnectionManager->serverBump()) {
                    serverBump->serverCert.resetAndLock(errDetails->peerCert());

                    // remember validation errors, if any
                    if (Ssl::Errors *errs = static_cast<Ssl::Errors*>(SSL_get_ex_data(ssl, ssl_ex_index_ssl_errors)))
                        serverBump->sslErrors = cbdataReference(errs);
                }
            }

            // For intercepted connections, set the host name to the server
            // certificate CN. Otherwise, we just hope that CONNECT is using
            // a user-entered address (a host name or a user-entered IP).
            const bool isConnectRequest = !request->clientConnectionManager->port->spoof_client_ip &&
                                          !request->clientConnectionManager->port->intercepted;
            if (request->flags.sslPeek && !isConnectRequest) {
                if (X509 *srvX509 = errDetails->peerCert()) {
                    if (const char *name = Ssl::CommonHostName(srvX509)) {
                        request->SetHost(name);
                        debugs(83, 3, HERE << "reset request host: " << name);
                    }
                }
            }

            ErrorState *const anErr = makeConnectingError(ERR_SECURE_CONNECT_FAIL);
            anErr->xerrno = sysErrNo;
            anErr->detail = errDetails;
            fail(anErr);

            if (serverConnection()->getPeer()) {
                peerConnectFailed(serverConnection()->getPeer());
            }

            serverConn->close();
            return;
        }
    }

    if (request->clientConnectionManager.valid()) {
        // remember the server certificate from the ErrorDetail object
        if (Ssl::ServerBump *serverBump = request->clientConnectionManager->serverBump()) {
            serverBump->serverCert.reset(SSL_get_peer_certificate(ssl));

            // remember validation errors, if any
            if (Ssl::Errors *errs = static_cast<Ssl::Errors *>(SSL_get_ex_data(ssl, ssl_ex_index_ssl_errors)))
                serverBump->sslErrors = cbdataReference(errs);
        }
    }

    if (serverConnection()->getPeer() && !SSL_session_reused(ssl)) {
        if (serverConnection()->getPeer()->sslSession)
            SSL_SESSION_free(serverConnection()->getPeer()->sslSession);

        serverConnection()->getPeer()->sslSession = SSL_get1_session(ssl);
    }

    dispatch();
}

void
FwdState::initiateSSL()
{
    SSL *ssl;
    SSL_CTX *sslContext = NULL;
    const CachePeer *peer = serverConnection()->getPeer();
    int fd = serverConnection()->fd;

    if (peer) {
        assert(peer->use_ssl);
        sslContext = peer->sslContext;
    } else {
        sslContext = Config.ssl_client.sslContext;
    }

    assert(sslContext);

    if ((ssl = SSL_new(sslContext)) == NULL) {
        debugs(83, DBG_IMPORTANT, "fwdInitiateSSL: Error allocating handle: " << ERR_error_string(ERR_get_error(), NULL)  );
        ErrorState *anErr = new ErrorState(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        // TODO: create Ssl::ErrorDetail with OpenSSL-supplied error code
        fail(anErr);
        self = NULL;		// refcounted
        return;
    }

    SSL_set_fd(ssl, fd);

    if (peer) {
        if (peer->ssldomain)
            SSL_set_ex_data(ssl, ssl_ex_index_server, peer->ssldomain);

#if NOT_YET

        else if (peer->name)
            SSL_set_ex_data(ssl, ssl_ex_index_server, peer->name);

#endif

        else
            SSL_set_ex_data(ssl, ssl_ex_index_server, peer->host);

        if (peer->sslSession)
            SSL_set_session(ssl, peer->sslSession);

    } else {
        // While we are peeking at the certificate, we may not know the server
        // name that the client will request (after interception or CONNECT)
        // unless it was the CONNECT request with a user-typed address.
        const char *hostname = request->GetHost();
        const bool hostnameIsIp = request->GetHostIsNumeric();
        const bool isConnectRequest = !request->clientConnectionManager->port->spoof_client_ip &&
                                      !request->clientConnectionManager->port->intercepted;
        if (!request->flags.sslPeek || isConnectRequest)
            SSL_set_ex_data(ssl, ssl_ex_index_server, (void*)hostname);

        // Use SNI TLS extension only when we connect directly
        // to the origin server and we know the server host name.
        if (!hostnameIsIp)
            Ssl::setClientSNI(ssl, hostname);
    }

    // Create the ACL check list now, while we have access to more info.
    // The list is used in ssl_verify_cb() and is freed in ssl_free().
    if (acl_access *acl = Config.ssl_client.cert_error) {
        ACLFilledChecklist *check = new ACLFilledChecklist(acl, request, dash_str);
        SSL_set_ex_data(ssl, ssl_ex_index_cert_error_check, check);
    }

    // store peeked cert to check SQUID_X509_V_ERR_CERT_CHANGE
    X509 *peeked_cert;
    if (request->clientConnectionManager.valid() &&
            request->clientConnectionManager->serverBump() &&
            (peeked_cert = request->clientConnectionManager->serverBump()->serverCert.get())) {
        CRYPTO_add(&(peeked_cert->references),1,CRYPTO_LOCK_X509);
        SSL_set_ex_data(ssl, ssl_ex_index_ssl_peeked_cert, peeked_cert);
    }

    fd_table[fd].ssl = ssl;
    fd_table[fd].read_method = &ssl_read_method;
    fd_table[fd].write_method = &ssl_write_method;
    negotiateSSL(fd);
}

#endif

void
FwdState::connectDone(const Comm::ConnectionPointer &conn, comm_err_t status, int xerrno)
{
    if (status != COMM_OK) {
        ErrorState *const anErr = makeConnectingError(ERR_CONNECT_FAIL);
        anErr->xerrno = xerrno;
        fail(anErr);

        /* it might have been a timeout with a partially open link */
        if (conn != NULL) {
            if (conn->getPeer())
                peerConnectFailed(conn->getPeer());

            conn->close();
        }
        retryOrBail();
        return;
    }

    serverConn = conn;
    flags.connected_okay = true;

    debugs(17, 3, HERE << serverConnection() << ": '" << entry->url() << "'" );

    comm_add_close_handler(serverConnection()->fd, fwdServerClosedWrapper, this);

    if (serverConnection()->getPeer())
        peerConnectSucceded(serverConnection()->getPeer());

#if USE_SSL
    if (!request->flags.pinned) {
        if ((serverConnection()->getPeer() && serverConnection()->getPeer()->use_ssl) ||
                (!serverConnection()->getPeer() && request->protocol == AnyP::PROTO_HTTPS) ||
                request->flags.sslPeek) {
            initiateSSL();
            return;
        }
    }
#endif

    dispatch();
}

void
FwdState::connectTimeout(int fd)
{
    debugs(17, 2, "fwdConnectTimeout: FD " << fd << ": '" << entry->url() << "'" );
    assert(serverDestinations[0] != NULL);
    assert(fd == serverDestinations[0]->fd);

    if (entry->isEmpty()) {
        ErrorState *anErr = new ErrorState(ERR_CONNECT_FAIL, HTTP_GATEWAY_TIMEOUT, request);
        anErr->xerrno = ETIMEDOUT;
        fail(anErr);

        /* This marks the peer DOWN ... */
        if (serverDestinations[0]->getPeer())
            peerConnectFailed(serverDestinations[0]->getPeer());
    }

    if (Comm::IsConnOpen(serverDestinations[0])) {
        serverDestinations[0]->close();
    }
}

/**
 * Called after Forwarding path selection (via peer select) has taken place.
 * And whenever forwarding needs to attempt a new connection (routing failover)
 * We have a vector of possible localIP->remoteIP paths now ready to start being connected.
 */
void
FwdState::connectStart()
{
    assert(serverDestinations.size() > 0);

    debugs(17, 3, "fwdConnectStart: " << entry->url());

    if (n_tries == 0) // first attempt
        request->hier.first_conn_start = current_time;

    /* connection timeout */
    int ctimeout;
    if (serverDestinations[0]->getPeer()) {
        ctimeout = serverDestinations[0]->getPeer()->connect_timeout > 0 ?
                   serverDestinations[0]->getPeer()->connect_timeout : Config.Timeout.peer_connect;
    } else {
        ctimeout = Config.Timeout.connect;
    }

    /* calculate total forwarding timeout ??? */
    int ftimeout = Config.Timeout.forward - (squid_curtime - start_t);
    if (ftimeout < 0)
        ftimeout = 5;

    if (ftimeout < ctimeout)
        ctimeout = ftimeout;

    if (serverDestinations[0]->getPeer() && request->flags.sslBumped) {
        debugs(50, 4, "fwdConnectStart: Ssl bumped connections through parrent proxy are not allowed");
        ErrorState *anErr = new ErrorState(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, request);
        fail(anErr);
        self = NULL; // refcounted
        return;
    }

    request->flags.pinned = 0; // XXX: what if the ConnStateData set this to flag existing credentials?
    // XXX: answer: the peer selection *should* catch it and give us only the pinned peer. so we reverse the =0 step below.
    // XXX: also, logs will now lie if pinning is broken and leads to an error message.
    if (serverDestinations[0]->peerType == PINNED) {
        ConnStateData *pinned_connection = request->pinnedConnection();
        debugs(17,7, "pinned peer connection: " << pinned_connection);
        // pinned_connection may become nil after a pconn race
        if (pinned_connection)
            serverConn = pinned_connection->validatePinnedConnection(request, serverDestinations[0]->getPeer());
        else
            serverConn = NULL;
        if (Comm::IsConnOpen(serverConn)) {
            flags.connected_okay = true;
#if 0
            if (!serverConn->getPeer())
                serverConn->peerType = HIER_DIRECT;
#endif
            ++n_tries;
            request->flags.pinned = 1;
            if (pinned_connection->pinnedAuth())
                request->flags.auth = 1;
            comm_add_close_handler(serverConn->fd, fwdServerClosedWrapper, this);
            // the server may close the pinned connection before this request
            pconnRace = racePossible;
            dispatch();
            return;
        }
        // Pinned connection failure.
        debugs(17,2,HERE << "Pinned connection failed: " << pinned_connection);
        ErrorState *anErr = new ErrorState(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE, request);
        fail(anErr);
        self = NULL; // refcounted
        return;
    }

    // Use pconn to avoid opening a new connection.
    const char *host = NULL;
    if (!serverDestinations[0]->getPeer())
        host = request->GetHost();

    Comm::ConnectionPointer temp;
    // Avoid pconns after races so that the same client does not suffer twice.
    // This does not increase the total number of connections because we just
    // closed the connection that failed the race. And re-pinning assumes this.
    if (pconnRace != raceHappened)
        temp = fwdPconnPool->pop(serverDestinations[0], host, checkRetriable());

    const bool openedPconn = Comm::IsConnOpen(temp);
    pconnRace = openedPconn ? racePossible : raceImpossible;

    // if we found an open persistent connection to use. use it.
    if (openedPconn) {
        serverConn = temp;
        flags.connected_okay = true;
        debugs(17, 3, HERE << "reusing pconn " << serverConnection());
        ++n_tries;

        if (!serverConnection()->getPeer())
            ++origin_tries;

        comm_add_close_handler(serverConnection()->fd, fwdServerClosedWrapper, this);

        /* Update server side TOS and Netfilter mark on the connection. */
        if (Ip::Qos::TheConfig.isAclTosActive()) {
            temp->tos = GetTosToServer(request);
            Ip::Qos::setSockTos(temp, temp->tos);
        }
#if SO_MARK
        if (Ip::Qos::TheConfig.isAclNfmarkActive()) {
            temp->nfmark = GetNfmarkToServer(request);
            Ip::Qos::setSockNfmark(temp, temp->nfmark);
        }
#endif

        dispatch();
        return;
    }

    // We will try to open a new connection, possibly to the same destination.
    // We reset serverDestinations[0] in case we are using it again because
    // ConnOpener modifies its destination argument.
    serverDestinations[0]->local.SetPort(0);
    serverConn = NULL;

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    /* Get the server side TOS and Netfilter mark to be set on the connection. */
    if (Ip::Qos::TheConfig.isAclTosActive()) {
        serverDestinations[0]->tos = GetTosToServer(request);
    }
#if SO_MARK && USE_LIBCAP
    serverDestinations[0]->nfmark = GetNfmarkToServer(request);
    debugs(17, 3, "fwdConnectStart: got outgoing addr " << serverDestinations[0]->local << ", tos " << int(serverDestinations[0]->tos)
           << ", netfilter mark " << serverDestinations[0]->nfmark);
#else
    serverDestinations[0]->nfmark = 0;
    debugs(17, 3, "fwdConnectStart: got outgoing addr " << serverDestinations[0]->local << ", tos " << int(serverDestinations[0]->tos));
#endif

    calls.connector = commCbCall(17,3, "fwdConnectDoneWrapper", CommConnectCbPtrFun(fwdConnectDoneWrapper, this));
    Comm::ConnOpener *cs = new Comm::ConnOpener(serverDestinations[0], calls.connector, ctimeout);
    if (host)
        cs->setHost(host);
    AsyncJob::Start(cs);
}

void
FwdState::dispatch()
{
    debugs(17, 3, HERE << clientConn << ": Fetching '" << RequestMethodStr(request->method) << " " << entry->url() << "'");
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(Comm::IsConnOpen(serverConn));

    fd_note(serverConnection()->fd, entry->url());

    fd_table[serverConnection()->fd].noteUse(fwdPconnPool);

    /*assert(!EBIT_TEST(entry->flags, ENTRY_DISPATCHED)); */
    assert(entry->ping_status != PING_WAITING);

    assert(entry->lock_count);

    EBIT_SET(entry->flags, ENTRY_DISPATCHED);

    netdbPingSite(request->GetHost());

    /* Retrieves remote server TOS or MARK value, and stores it as part of the
     * original client request FD object. It is later used to forward
     * remote server's TOS/MARK in the response to the client in case of a MISS.
     */
    if (Ip::Qos::TheConfig.isHitNfmarkActive()) {
        if (Comm::IsConnOpen(clientConn) && Comm::IsConnOpen(serverConnection())) {
            fde * clientFde = &fd_table[clientConn->fd]; // XXX: move the fd_table access into Ip::Qos
            /* Get the netfilter mark for the connection */
            Ip::Qos::getNfmarkFromServer(serverConnection(), clientFde);
        }
    }

#if _SQUID_LINUX_
    /* Bug 2537: The TOS forward part of QOS only applies to patched Linux kernels. */
    if (Ip::Qos::TheConfig.isHitTosActive()) {
        if (Comm::IsConnOpen(clientConn)) {
            fde * clientFde = &fd_table[clientConn->fd]; // XXX: move the fd_table access into Ip::Qos
            /* Get the TOS value for the packet */
            Ip::Qos::getTosFromServer(serverConnection(), clientFde);
        }
    }
#endif

#if USE_SSL
    if (request->flags.sslPeek) {
        CallJobHere1(17, 4, request->clientConnectionManager, ConnStateData,
                     ConnStateData::httpsPeeked, serverConnection());
        unregister(serverConn); // async call owns it now
        complete(); // destroys us
        return;
    }
#endif

    if (serverConnection()->getPeer() != NULL) {
        ++ serverConnection()->getPeer()->stats.fetches;
        request->peer_login = serverConnection()->getPeer()->login;
        request->peer_domain = serverConnection()->getPeer()->domain;
        httpStart(this);
    } else {
        assert(!request->flags.sslPeek);
        request->peer_login = NULL;
        request->peer_domain = NULL;

        switch (request->protocol) {
#if USE_SSL

        case AnyP::PROTO_HTTPS:
            httpStart(this);
            break;
#endif

        case AnyP::PROTO_HTTP:
            httpStart(this);
            break;

        case AnyP::PROTO_GOPHER:
            gopherStart(this);
            break;

        case AnyP::PROTO_FTP:
            ftpStart(this);
            break;

        case AnyP::PROTO_CACHE_OBJECT:

        case AnyP::PROTO_INTERNAL:

        case AnyP::PROTO_URN:
            fatal_dump("Should never get here");
            break;

        case AnyP::PROTO_WHOIS:
            whoisStart(this);
            break;

        case AnyP::PROTO_WAIS:	/* Not implemented */

        default:
            debugs(17, DBG_IMPORTANT, "WARNING: Cannot retrieve '" << entry->url() << "'.");
            ErrorState *anErr = new ErrorState(ERR_UNSUP_REQ, HTTP_BAD_REQUEST, request);
            fail(anErr);
            // Set the dont_retry flag because this is not a transient (network) error.
            flags.dont_retry = 1;
            if (Comm::IsConnOpen(serverConn)) {
                serverConn->close();
            }
            break;
        }
    }
}

/*
 * FwdState::reforward
 *
 * returns TRUE if the transaction SHOULD be re-forwarded to the
 * next choice in the serverDestinations list.  This method is called when
 * server-side communication completes normally, or experiences
 * some error after receiving the end of HTTP headers.
 */
int
FwdState::reforward()
{
    StoreEntry *e = entry;
    http_status s;

    if (EBIT_TEST(e->flags, ENTRY_ABORTED)) {
        debugs(17, 3, HERE << "entry aborted");
        return 0;
    }

    assert(e->store_status == STORE_PENDING);
    assert(e->mem_obj);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif

    debugs(17, 3, HERE << e->url() << "?" );

    if (!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
        debugs(17, 3, HERE << "No, ENTRY_FWD_HDR_WAIT isn't set");
        return 0;
    }

    if (n_tries > Config.forward_max_tries)
        return 0;

    if (origin_tries > 1)
        return 0;

    if (request->bodyNibbled())
        return 0;

    if (serverDestinations.size() <= 1) {
        // NP: <= 1 since total count includes the recently failed one.
        debugs(17, 3, HERE << "No alternative forwarding paths left");
        return 0;
    }

    s = e->getReply()->sline.status;
    debugs(17, 3, HERE << "status " << s);
    return reforwardableStatus(s);
}

/**
 * Create "503 Service Unavailable" or "504 Gateway Timeout" error depending
 * on whether this is a validation request. RFC 2616 says that we MUST reply
 * with "504 Gateway Timeout" if validation fails and cached reply has
 * proxy-revalidate, must-revalidate or s-maxage Cache-Control directive.
 */
ErrorState *
FwdState::makeConnectingError(const err_type type) const
{
    return new ErrorState(type, request->flags.needValidation ?
                          HTTP_GATEWAY_TIMEOUT : HTTP_SERVICE_UNAVAILABLE, request);
}

static void
fwdStats(StoreEntry * s)
{
    int i;
    int j;
    storeAppendPrintf(s, "Status");

    for (j = 1; j < MAX_FWD_STATS_IDX; ++j) {
        storeAppendPrintf(s, "\ttry#%d", j);
    }

    storeAppendPrintf(s, "\n");

    for (i = 0; i <= (int) HTTP_INVALID_HEADER; ++i) {
        if (FwdReplyCodes[0][i] == 0)
            continue;

        storeAppendPrintf(s, "%3d", i);

        for (j = 0; j <= MAX_FWD_STATS_IDX; ++j) {
            storeAppendPrintf(s, "\t%d", FwdReplyCodes[j][i]);
        }

        storeAppendPrintf(s, "\n");
    }
}

/**** STATIC MEMBER FUNCTIONS *************************************************/

bool
FwdState::reforwardableStatus(http_status s)
{
    switch (s) {

    case HTTP_BAD_GATEWAY:

    case HTTP_GATEWAY_TIMEOUT:
        return true;

    case HTTP_FORBIDDEN:

    case HTTP_INTERNAL_SERVER_ERROR:

    case HTTP_NOT_IMPLEMENTED:

    case HTTP_SERVICE_UNAVAILABLE:
        return Config.retry.onerror;

    default:
        return false;
    }

    /* NOTREACHED */
}

/**
 * Decide where details need to be gathered to correctly describe a persistent connection.
 * What is needed:
 *  -  the address/port details about this link
 *  -  domain name of server at other end of this link (either peer or requested host)
 */
void
FwdState::pconnPush(Comm::ConnectionPointer &conn, const char *domain)
{
    if (conn->getPeer()) {
        fwdPconnPool->push(conn, NULL);
    } else {
        fwdPconnPool->push(conn, domain);
    }
}

void
FwdState::initModule()
{
    RegisterWithCacheManager();
}

void
FwdState::RegisterWithCacheManager(void)
{
    Mgr::RegisterAction("forward", "Request Forwarding Statistics", fwdStats, 0, 1);
}

void
FwdState::logReplyStatus(int tries, http_status status)
{
    if (status > HTTP_INVALID_HEADER)
        return;

    assert(tries >= 0);

    if (tries > MAX_FWD_STATS_IDX)
        tries = MAX_FWD_STATS_IDX;

    ++ FwdReplyCodes[tries][status];
}

/**** PRIVATE NON-MEMBER FUNCTIONS ********************************************/

/*
 * DPW 2007-05-19
 * Formerly static, but now used by client_side_request.cc
 */
/// Checks for a TOS value to apply depending on the ACL
tos_t
aclMapTOS(acl_tos * head, ACLChecklist * ch)
{
    acl_tos *l;

    for (l = head; l; l = l->next) {
        if (!l->aclList || ch->fastCheck(l->aclList) == ACCESS_ALLOWED)
            return l->tos;
    }

    return 0;
}

/// Checks for a netfilter mark value to apply depending on the ACL
nfmark_t
aclMapNfmark(acl_nfmark * head, ACLChecklist * ch)
{
    acl_nfmark *l;

    for (l = head; l; l = l->next) {
        if (!l->aclList || ch->fastCheck(l->aclList) == ACCESS_ALLOWED)
            return l->nfmark;
    }

    return 0;
}

void
getOutgoingAddress(HttpRequest * request, Comm::ConnectionPointer conn)
{
    // skip if an outgoing address is already set.
    if (!conn->local.IsAnyAddr()) return;

    // ensure that at minimum the wildcard local matches remote protocol
    if (conn->remote.IsIPv4())
        conn->local.SetIPv4();

    // maybe use TPROXY client address
    if (request && request->flags.spoofClientIp) {
        if (!conn->getPeer() || !conn->getPeer()->options.no_tproxy) {
#if FOLLOW_X_FORWARDED_FOR && LINUX_NETFILTER
            if (Config.onoff.tproxy_uses_indirect_client)
                conn->local = request->indirect_client_addr;
            else
#endif
                conn->local = request->client_addr;
            // some flags need setting on the socket to use this address
            conn->flags |= COMM_DOBIND;
            conn->flags |= COMM_TRANSPARENT;
            return;
        }
        // else no tproxy today ...
    }

    if (!Config.accessList.outgoing_address) {
        return; // anything will do.
    }

    ACLFilledChecklist ch(NULL, request, NULL);
    ch.dst_peer = conn->getPeer();
    ch.dst_addr = conn->remote;

    // TODO use the connection details in ACL.
    // needs a bit of rework in ACLFilledChecklist to use Comm::Connection instead of ConnStateData

    AclAddress *l;
    for (l = Config.accessList.outgoing_address; l; l = l->next) {

        /* check if the outgoing address is usable to the destination */
        if (conn->remote.IsIPv4() != l->addr.IsIPv4()) continue;

        /* check ACLs for this outgoing address */
        if (!l->aclList || ch.fastCheck(l->aclList) == ACCESS_ALLOWED) {
            conn->local = l->addr;
            return;
        }
    }
}

tos_t
GetTosToServer(HttpRequest * request)
{
    ACLFilledChecklist ch(NULL, request, NULL);
    return aclMapTOS(Ip::Qos::TheConfig.tosToServer, &ch);
}

nfmark_t
GetNfmarkToServer(HttpRequest * request)
{
    ACLFilledChecklist ch(NULL, request, NULL);
    return aclMapNfmark(Ip::Qos::TheConfig.nfmarkToServer, &ch);
}
