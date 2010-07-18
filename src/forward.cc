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
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "CacheManager.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "CommCalls.h"
#include "event.h"
#include "errorpage.h"
#include "fde.h"
#include "forward.h"
#include "hier_code.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "pconn.h"
#include "PeerSelectState.h"
#include "SquidTime.h"
#include "Store.h"
#include "icmp/net_db.h"
#include "ip/Intercept.h"


static PSC fwdStartCompleteWrapper;
static PF fwdServerClosedWrapper;
#if USE_SSL
static PF fwdNegotiateSSLWrapper;
#endif
static CNCB fwdConnectDoneWrapper;

static OBJH fwdStats;

#define MAX_FWD_STATS_IDX 9
static int FwdReplyCodes[MAX_FWD_STATS_IDX + 1][HTTP_INVALID_HEADER + 1];

#if WIP_FWD_LOG
static void fwdLog(FwdState * fwdState);
static Logfile *logfile = NULL;
#endif

static PconnPool *fwdPconnPool = new PconnPool("server-side");
CBDATA_CLASS_INIT(FwdState);

void
FwdState::abort(void* d)
{
    FwdState* fwd = (FwdState*)d;
    Pointer tmp = fwd; // Grab a temporary pointer to keep the object alive during our scope.

    if (fwd->paths.size() > 0 && fwd->paths[0]->isOpen()) {
        comm_remove_close_handler(fwd->paths[0]->fd, fwdServerClosedWrapper, fwd);
    }
    fwd->paths.clean();
    fwd->self = NULL;
}

/**** PUBLIC INTERFACE ********************************************************/

FwdState::FwdState(int fd, StoreEntry * e, HttpRequest * r)
{
    entry = e;
    client_fd = fd;
    request = HTTPMSGLOCK(r);
    start_t = squid_curtime;

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
    peerSelect(&paths, request, entry, fwdStartCompleteWrapper, this);
}

void
FwdState::completed()
{
    if (flags.forward_completed == 1) {
        debugs(17, 1, HERE << "FwdState::completed called on a completed request! Bad!");
        return;
    }

    flags.forward_completed = 1;

#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif
#if WIP_FWD_LOG

    log();
#endif

    if (entry->store_status == STORE_PENDING) {
        if (entry->isEmpty()) {
            assert(err);
            errorAppendEntry(entry, err);
            err = NULL;
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

    HTTPMSGUNLOCK(request);

    if (err)
        errorStateFree(err);

    entry->unregisterAbort();

    entry->unlock();

    entry = NULL;

    if (paths.size() > 0 && paths[0]->isOpen()) {
        comm_remove_close_handler(paths[0]->fd, fwdServerClosedWrapper, this);
        debugs(17, 3, HERE << "closing FD " << paths[0]->fd);
        paths[0]->close();
    }

    paths.clean();

    debugs(17, 3, HERE << "FwdState destructor done");
}

/**
 * This is the entry point for client-side to start forwarding
 * a transaction.  It is a static method that may or may not
 * allocate a FwdState.
 */
void
FwdState::fwdStart(int client_fd, StoreEntry *entry, HttpRequest *request)
{
    /** \note
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if ( Config.accessList.miss && !request->client_addr.IsNoAddr() &&
            request->protocol != PROTO_INTERNAL && request->protocol != PROTO_CACHEOBJ) {
        /**
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         */
        ACLFilledChecklist ch(Config.accessList.miss, request, NULL);
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        int answer = ch.fastCheck();

        if (answer == 0) {
            err_type page_id;
            page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName, 1);

            if (page_id == ERR_NONE)
                page_id = ERR_FORWARDING_DENIED;

            ErrorState *anErr = errorCon(page_id, HTTP_FORBIDDEN, request);

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
        ErrorState *anErr = errorCon(ERR_SHUTTING_DOWN, HTTP_SERVICE_UNAVAILABLE, request);
        errorAppendEntry(entry, anErr);	// frees anErr
        return;
    }

    switch (request->protocol) {

    case PROTO_INTERNAL:
        internalStart(request, entry);
        return;

    case PROTO_CACHEOBJ:
        CacheManager::GetInstance()->Start(client_fd, request, entry);
        return;

    case PROTO_URN:
        urnStart(request, entry);
        return;

    default:
        FwdState::Pointer fwd = new FwdState(client_fd, entry, request);
        fwd->start(fwd);
        return;
    }

    /* NOTREACHED */
}

void
FwdState::startComplete()
{
    debugs(17, 3, HERE << entry->url() );

    if (paths.size() > 0) {
        connectStart();
    } else {
        debugs(17, 3, HERE << entry->url()  );
        ErrorState *anErr = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, request);
        anErr->xerrno = errno;
        fail(anErr);
        self = NULL;       // refcounted
    }
}

void
FwdState::fail(ErrorState * errorState)
{
    debugs(17, 3, HERE << err_type_str[errorState->type] << " \"" << httpStatusString(errorState->httpStatus) << "\"\n\t" << entry->url()  );

    if (err)
        errorStateFree(err);

    err = errorState;

    if (!errorState->request)
        errorState->request = HTTPMSGLOCK(request);
}

/**
 * Frees fwdState without closing FD or generating an abort
 */
void
FwdState::unregister(int fd)
{
    debugs(17, 3, HERE << entry->url()  );
    assert(fd == paths[0]->fd);
    assert(fd > -1);
    comm_remove_close_handler(fd, fwdServerClosedWrapper, this);
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
    assert(entry->store_status == STORE_PENDING);
    debugs(17, 3, HERE << entry->url() << "\n\tstatus " << entry->getReply()->sline.status  );
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    logReplyStatus(n_tries, entry->getReply()->sline.status);

    if (reforward()) {
        debugs(17, 3, HERE << "re-forwarding " << entry->getReply()->sline.status << " " << entry->url());

        if (paths[0]->fd > -1)
            unregister(paths[0]->fd);

        entry->reset();

        /* the call to reforward() has already dropped the last path off the
         * selection list. all we have now are the next path(s) to be tried.
         */
        connectStart();
    } else {
        debugs(17, 3, HERE << "server FD " << paths[0]->fd << " not re-forwarding status " << entry->getReply()->sline.status);
        EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
        entry->complete();

        if (paths[0]->fd < 0)
            completed();

        self = NULL; // refcounted
    }
}


/**** CALLBACK WRAPPERS ************************************************************/

static void
fwdStartCompleteWrapper(Comm::Paths * unused, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->startComplete();
}

static void
fwdServerClosedWrapper(int fd, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->serverClosed(fd);
}

#if 0
static void
fwdConnectStartWrapper(void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->connectStart();
}
#endif

#if USE_SSL
static void
fwdNegotiateSSLWrapper(int fd, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->negotiateSSL(fd);
}
#endif

void
fwdConnectDoneWrapper(Comm::ConnectionPointer &conn, comm_err_t status, int xerrno, void *data)
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

    if (!checkRetriable())
        return false;

    if (request->bodyNibbled())
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
    /* If there is a request body then Squid can only try once
     * even if the method is indempotent
     */

    if (request->body_pipe != NULL)
        return false;

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
    assert(paths[0]->fd == fd);

    if (paths[0]->getPeer()) {
        paths[0]->getPeer()->stats.conn_open--;
    }

    retryOrBail();
}

void
FwdState::retryOrBail()
{
    if (!self) { // we have aborted before the server called us back
        debugs(17, 5, HERE << "not retrying because of earlier abort");
        // we will be destroyed when the server clears its Pointer to us
        return;
    }

    if (checkRetry()) {
        debugs(17, 3, HERE << "re-forwarding (" << n_tries << " tries, " << (squid_curtime - start_t) << " secs)");

        paths.shift(); // last one failed. try another.

        if (paths.size() > 0) {
            /* Ditch error page if it was created before.
             * A new one will be created if there's another problem */
            if (err) {
                errorStateFree(err);
                err = NULL;
            }

            connectStart();
            return;
        }
        // else bail. no more paths possible to try.
    }

    if (!err && shutting_down) {
        errorCon(ERR_SHUTTING_DOWN, HTTP_SERVICE_UNAVAILABLE, request);
    }

    self = NULL;	// refcounted
}

// called by the server that failed after calling unregister()
void
FwdState::handleUnregisteredServerEnd()
{
    debugs(17, 2, HERE << "self=" << self << " err=" << err << ' ' << entry->url());
    assert(paths[0]->fd < 0);
    retryOrBail();
}

#if USE_SSL
void
FwdState::negotiateSSL(int fd)
{
    SSL *ssl = fd_table[fd].ssl;
    int ret;

    if ((ret = SSL_connect(ssl)) <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);

        switch (ssl_error) {

        case SSL_ERROR_WANT_READ:
            commSetSelect(fd, COMM_SELECT_READ, fwdNegotiateSSLWrapper, this, 0);
            return;

        case SSL_ERROR_WANT_WRITE:
            commSetSelect(fd, COMM_SELECT_WRITE, fwdNegotiateSSLWrapper, this, 0);
            return;

        default:
            debugs(81, 1, "fwdNegotiateSSL: Error negotiating SSL connection on FD " << fd <<
                   ": " << ERR_error_string(ERR_get_error(), NULL) << " (" << ssl_error <<
                   "/" << ret << "/" << errno << ")");
            ErrorState *anErr = errorCon(ERR_SECURE_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
#ifdef EPROTO

            anErr->xerrno = EPROTO;
#else

            anErr->xerrno = EACCES;
#endif

            fail(anErr);

            if (paths[0]->getPeer()) {
                peerConnectFailed(paths[0]->getPeer());
                paths[0]->getPeer()->stats.conn_open--;
            }

            paths[0]->close();
            return;
        }
    }

    if (paths[0]->getPeer() && !SSL_session_reused(ssl)) {
        if (paths[0]->getPeer()->sslSession)
            SSL_SESSION_free(paths[0]->getPeer()->sslSession);

        paths[0]->getPeer()->sslSession = SSL_get1_session(ssl);
    }

    dispatch();
}

void
FwdState::initiateSSL()
{
    SSL *ssl;
    SSL_CTX *sslContext = NULL;
    const peer *peer = paths[0]->getPeer();
    int fd = paths[0]->fd;

    if (peer) {
        assert(peer->use_ssl);
        sslContext = peer->sslContext;
    } else {
        sslContext = Config.ssl_client.sslContext;
    }

    assert(sslContext);

    if ((ssl = SSL_new(sslContext)) == NULL) {
        debugs(83, 1, "fwdInitiateSSL: Error allocating handle: " << ERR_error_string(ERR_get_error(), NULL)  );
        ErrorState *anErr = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        anErr->xerrno = errno;
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
        SSL_set_ex_data(ssl, ssl_ex_index_server, (void*)request->GetHost());
    }

    // Create the ACL check list now, while we have access to more info.
    // The list is used in ssl_verify_cb() and is freed in ssl_free().
    if (acl_access *acl = Config.ssl_client.cert_error) {
        ACLFilledChecklist *check = new ACLFilledChecklist(acl, request, dash_str);
        check->fd(fd);
        SSL_set_ex_data(ssl, ssl_ex_index_cert_error_check, check);
    }

    fd_table[fd].ssl = ssl;
    fd_table[fd].read_method = &ssl_read_method;
    fd_table[fd].write_method = &ssl_write_method;
    negotiateSSL(fd);
}

#endif

void
FwdState::connectDone(Comm::ConnectionPointer &conn, comm_err_t status, int xerrno)
{
    if (status != COMM_OK) {
        ErrorState *anErr = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
        anErr->xerrno = xerrno;
        fail(anErr);

        /* it might have been a timeout with a partially open link */
        if (paths.size() > 0) {
            if (paths[0]->getPeer())
                peerConnectFailed(paths[0]->getPeer());

            paths[0]->close();
        }
        retryOrBail();
        return;
    }

#if REDUNDANT_NOW
    if (Config.onoff.log_ip_on_direct && paths[0]->peer_type == HIER_DIRECT)
        updateHierarchyInfo();
#endif

    debugs(17, 3, "FD " << paths[0]->fd << ": '" << entry->url() << "'" );

    comm_add_close_handler(paths[0]->fd, fwdServerClosedWrapper, this);

    if (paths[0]->getPeer())
        peerConnectSucceded(paths[0]->getPeer());

    updateHierarchyInfo();

#if USE_SSL
    if ((paths[0]->getPeer() && paths[0]->getPeer()->use_ssl) ||
            (!paths[0]->getPeer() && request->protocol == PROTO_HTTPS)) {
        initiateSSL();
        return;
    }
#endif

    dispatch();
}

void
FwdState::connectTimeout(int fd)
{
    debugs(17, 2, "fwdConnectTimeout: FD " << fd << ": '" << entry->url() << "'" );
    assert(fd == paths[0]->fd);

    if (Config.onoff.log_ip_on_direct && paths[0]->peer_type == HIER_DIRECT)
        updateHierarchyInfo();

    if (entry->isEmpty()) {
        ErrorState *anErr = errorCon(ERR_CONNECT_FAIL, HTTP_GATEWAY_TIMEOUT, request);
        anErr->xerrno = ETIMEDOUT;
        fail(anErr);

        /* This marks the peer DOWN ... */
        if (paths.size() > 0)
            if (paths[0]->getPeer())
                peerConnectFailed(paths[0]->getPeer());
    }

    paths[0]->close();
}

/**
 * Called after Forwarding path selection (via peer select) has taken place.
 * And whenever forwarding needs to attempt a new connection (routing failover)
 * We have a vector of possible localIP->remoteIP paths now ready to start being connected.
 */
void
FwdState::connectStart()
{
    debugs(17, 3, "fwdConnectStart: " << entry->url());

    if (n_tries == 0) // first attempt
        request->hier.first_conn_start = current_time;

    Comm::ConnectionPointer conn = paths[0];

    /* connection timeout */
    int ctimeout;
    if (conn->getPeer()) {
        ctimeout = conn->getPeer()->connect_timeout > 0 ? conn->getPeer()->connect_timeout : Config.Timeout.peer_connect;
    } else {
        ctimeout = Config.Timeout.connect;
    }

    /* calculate total forwarding timeout ??? */
    int ftimeout = Config.Timeout.forward - (squid_curtime - start_t);
    if (ftimeout < 0)
        ftimeout = 5;

    if (ftimeout < ctimeout)
        ctimeout = ftimeout;

    request->flags.pinned = 0;
    if (conn->peer_type == PINNED) {
        ConnStateData *pinned_connection = request->pinnedConnection();
        assert(pinned_connection);
        conn->fd = pinned_connection->validatePinnedConnection(request, conn->getPeer());
        if (conn->isOpen()) {
            pinned_connection->unpinConnection();
#if 0
            if (!conn->getPeer())
                conn->peer_type = HIER_DIRECT;
#endif
            n_tries++;
            request->flags.pinned = 1;
            if (pinned_connection->pinnedAuth())
                request->flags.auth = 1;
            updateHierarchyInfo();
            FwdState::connectDone(conn, COMM_OK, 0);
            return;
        }
        /* Failure. Fall back on next path */
        debugs(17,2,HERE << " Pinned connection " << pinned_connection << " not valid. Releasing.");
        request->releasePinnedConnection();
        paths.shift();
        conn = NULL; // maybe release the conn memory. it's not needed by us anyway.
        connectStart();
        return;
    }

// TODO: now that we are dealing with actual IP->IP links. should we still anchor pconn on hostname?
//	or on the remote IP+port?
// that could reduce the pconns per virtual server a fair amount
// but would prevent crossover between servers hosting the one domain
// this currently opens the possibility that conn will lie about where the FD goes.

    const char *host;
    int port;
    if (conn->getPeer()) {
        host = conn->getPeer()->host;
        port = conn->getPeer()->http_port;
        conn->fd = fwdPconnPool->pop(conn->getPeer()->name, conn->getPeer()->http_port, request->GetHost(), conn->local, checkRetriable());
    } else {
        host = request->GetHost();
        port = request->port;
        conn->fd = fwdPconnPool->pop(host, port, NULL, conn->local, checkRetriable());
    }
    conn->remote.SetPort(port);

    if (conn->isOpen()) {
        debugs(17, 3, HERE << "reusing pconn FD " << conn->fd);
        n_tries++;

        if (!conn->getPeer())
            origin_tries++;

        updateHierarchyInfo();

        comm_add_close_handler(conn->fd, fwdServerClosedWrapper, this);

        dispatch();
        return;
    }

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    AsyncCall::Pointer call = commCbCall(17,3, "fwdConnectDoneWrapper", CommConnectCbPtrFun(fwdConnectDoneWrapper, this));
    Comm::ConnOpener *cs = new Comm::ConnOpener(paths[0], call, ctimeout);
    cs->setHost(host);
    AsyncJob::AsyncStart(cs);
}

void
FwdState::dispatch()
{
    debugs(17, 3, "fwdDispatch: FD " << client_fd << ": Fetching '" << RequestMethodStr(request->method) << " " << entry->url() << "'" );
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(paths.size() > 0 && paths[0]->fd > -1);

    fd_note(paths[0]->fd, entry->url());

    fd_table[paths[0]->fd].noteUse(fwdPconnPool);

    /*assert(!EBIT_TEST(entry->flags, ENTRY_DISPATCHED)); */
    assert(entry->ping_status != PING_WAITING);

    assert(entry->lock_count);

    EBIT_SET(entry->flags, ENTRY_DISPATCHED);

    netdbPingSite(request->GetHost());

#if USE_ZPH_QOS && defined(_SQUID_LINUX_)
    /* Bug 2537: This part of ZPH only applies to patched Linux kernels. */

    /* Retrieves remote server TOS value, and stores it as part of the
     * original client request FD object. It is later used to forward
     * remote server's TOS in the response to the client in case of a MISS.
     */
    fde * clientFde = &fd_table[client_fd];
    if (clientFde) {
        int tos = 1;
        int tos_len = sizeof(tos);
        clientFde->upstreamTOS = 0;
        if (setsockopt(paths[0]->fd,SOL_IP,IP_RECVTOS,&tos,tos_len)==0) {
            unsigned char buf[512];
            int len = 512;
            if (getsockopt(paths[0]->fd,SOL_IP,IP_PKTOPTIONS,buf,(socklen_t*)&len) == 0) {
                /* Parse the PKTOPTIONS structure to locate the TOS data message
                 * prepared in the kernel by the ZPH incoming TCP TOS preserving
                 * patch.
                 */
                unsigned char * pbuf = buf;
                while (pbuf-buf < len) {
                    struct cmsghdr *o = (struct cmsghdr*)pbuf;
                    if (o->cmsg_len<=0)
                        break;

                    if (o->cmsg_level == SOL_IP && o->cmsg_type == IP_TOS) {
                        int *tmp = (int*)CMSG_DATA(o);
                        clientFde->upstreamTOS = (unsigned char)*tmp;
                        break;
                    }
                    pbuf += CMSG_LEN(o->cmsg_len);
                }
            } else {
                debugs(33, DBG_IMPORTANT, "ZPH: error in getsockopt(IP_PKTOPTIONS) on FD " << paths[0]->fd << " " << xstrerror());
            }
        } else {
            debugs(33, DBG_IMPORTANT, "ZPH: error in setsockopt(IP_RECVTOS) on FD " << paths[0]->fd << " " << xstrerror());
        }
    }
#endif

    if (paths.size() > 0 && paths[0]->getPeer() != NULL) {
        paths[0]->getPeer()->stats.fetches++;
        request->peer_login = paths[0]->getPeer()->login;
        request->peer_domain = paths[0]->getPeer()->domain;
        httpStart(this);
    } else {
        request->peer_login = NULL;
        request->peer_domain = NULL;

        switch (request->protocol) {
#if USE_SSL

        case PROTO_HTTPS:
            httpStart(this);
            break;
#endif

        case PROTO_HTTP:
            httpStart(this);
            break;

        case PROTO_GOPHER:
            gopherStart(this);
            break;

        case PROTO_FTP:
            ftpStart(this);
            break;

        case PROTO_CACHEOBJ:

        case PROTO_INTERNAL:

        case PROTO_URN:
            fatal_dump("Should never get here");
            break;

        case PROTO_WHOIS:
            whoisStart(this);
            break;

        case PROTO_WAIS:	/* Not implemented */

        default:
            debugs(17, 1, "fwdDispatch: Cannot retrieve '" << entry->url() << "'" );
            ErrorState *anErr = errorCon(ERR_UNSUP_REQ, HTTP_BAD_REQUEST, request);
            fail(anErr);
            /*
             * Force a persistent connection to be closed because
             * some Netscape browsers have a bug that sends CONNECT
             * requests as GET's over persistent connections.
             */
            request->flags.proxy_keepalive = 0;
            /*
             * Set the dont_retry flag becuase this is not a
             * transient (network) error; its a bug.
             */
            flags.dont_retry = 1;
            paths[0]->close();
            break;
        }
    }
}

/*
 * FwdState::reforward
 *
 * returns TRUE if the transaction SHOULD be re-forwarded to the
 * next choice in the FwdServers list.  This method is called when
 * server-side communication completes normally, or experiences
 * some error after receiving the end of HTTP headers.
 */
int
FwdState::reforward()
{
    StoreEntry *e = entry;
    http_status s;
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

    paths.shift();

    if (paths.size() > 0) {
        debugs(17, 3, HERE << "No alternative forwarding paths left");
        return 0;
    }

    s = e->getReply()->sline.status;
    debugs(17, 3, HERE << "status " << s);
    return reforwardableStatus(s);
}

static void
fwdStats(StoreEntry * s)
{
    int i;
    int j;
    storeAppendPrintf(s, "Status");

    for (j = 0; j <= MAX_FWD_STATS_IDX; j++) {
        storeAppendPrintf(s, "\ttry#%d", j + 1);
    }

    storeAppendPrintf(s, "\n");

    for (i = 0; i <= (int) HTTP_INVALID_HEADER; i++) {
        if (FwdReplyCodes[0][i] == 0)
            continue;

        storeAppendPrintf(s, "%3d", i);

        for (j = 0; j <= MAX_FWD_STATS_IDX; j++) {
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
 *  -  host name of server at other end of this link (either peer or requested host)
 *  -  port to which we connected the other end of this link (for peer or request)
 *  -  domain for which the connection is supposed to be used
 *  -  address of the client for which we made the connection
 */
void
FwdState::pconnPush(Comm::ConnectionPointer conn, const peer *_peer, const HttpRequest *req, const char *domain, Ip::Address &client_addr)
{
    if (_peer) {
        fwdPconnPool->push(conn->fd, _peer->name, _peer->http_port, domain, client_addr);
    } else {
        /* small performance improvement, using NULL for domain instead of listing it twice */
        /* although this will leave a gap open for url-rewritten domains to share a link */
        fwdPconnPool->push(conn->fd, req->GetHost(), req->port, NULL, client_addr);
    }

    /* XXX: remove this when Comm::Connection are stored in the pool
     * this only prevents the persistent FD being closed when the
     * Comm::Connection currently using it is destroyed.
     */
    conn->fd = -1;
}

void
FwdState::initModule()
{
#if WIP_FWD_LOG

    if (logfile)
        (void) 0;
    else if (NULL == Config.Log.forward)
        (void) 0;
    else
        logfile = logfileOpen(Config.Log.forward, 0, 1);

#endif

    RegisterWithCacheManager();
}

void
FwdState::RegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("forward", "Request Forwarding Statistics", fwdStats, 0, 1);
}

void
FwdState::logReplyStatus(int tries, http_status status)
{
    if (status > HTTP_INVALID_HEADER)
        return;

    assert(tries >= 0);

    if (tries > MAX_FWD_STATS_IDX)
        tries = MAX_FWD_STATS_IDX;

    FwdReplyCodes[tries][status]++;
}

/** From Comment #5 by Henrik Nordstrom made at
http://www.squid-cache.org/bugs/show_bug.cgi?id=2391 on 2008-09-19

updateHierarchyInfo should be called each time a new path has been
selected or when more information about the path is available (i.e. the
server IP), and when it's called it needs to be given reasonable
arguments describing the now selected path..

It does not matter from a functional perspective if it gets called a few
times more than what is really needed, but calling it too often may
obviously hurt performance.
*/
// updates HierarchyLogEntry, guessing nextHop and its format
void
FwdState::updateHierarchyInfo()
{
    assert(request);

    assert(paths.size() > 0);

    char nextHop[256]; // 

    if (paths[0]->getPeer()) {
        // went to peer, log peer host name
        snprintf(nextHop,256,"%s", paths[0]->getPeer()->name);
    } else {
        // went DIRECT, must honor log_ip_on_direct
        if (!Config.onoff.log_ip_on_direct)
            snprintf(nextHop,256,"%s",request->GetHost()); // domain name
        else
            paths[0]->remote.NtoA(nextHop, 256);
    }

    request->hier.peer_local_port = paths[0]->local.GetPort();

    assert(nextHop[0]);
    hierarchyNote(&request->hier, paths[0]->peer_type, nextHop);
}


/**** PRIVATE NON-MEMBER FUNCTIONS ********************************************/

/*
 * DPW 2007-05-19
 * Formerly static, but now used by client_side_request.cc
 */
int
aclMapTOS(acl_tos * head, ACLChecklist * ch)
{
    acl_tos *l;

    for (l = head; l; l = l->next) {
        if (!l->aclList || ch->matchAclListFast(l->aclList))
            return l->tos;
    }

    return 0;
}

void
getOutgoingAddress(HttpRequest * request, Comm::ConnectionPointer conn)
{
    /* skip if an outgoing address is already set. */
    if (!conn->local.IsAnyAddr()) return;

    // maybe use TPROXY client address
    if (request && request->flags.spoof_client_ip) {
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

    if (request) {
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.acl_uses_indirect_client)
            ch.src_addr = request->indirect_client_addr;
        else
#endif
            ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
    }

    acl_address *l;
    for (l = Config.accessList.outgoing_address; l; l = l->next) {

        /* check if the outgoing address is usable to the destination */
        if (conn->remote.IsIPv4() != l->addr.IsIPv4()) continue;

        /* check ACLs for this outgoing address */
        if (!l->aclList || ch.matchAclListFast(l->aclList)) {
            conn->local = l->addr;
            return;
        }
    }
}

unsigned long
getOutgoingTOS(HttpRequest * request)
{
    ACLFilledChecklist ch(NULL, request, NULL);

    if (request) {
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
    }

    return aclMapTOS(Config.accessList.outgoing_tos, &ch);
}


/**** WIP_FWD_LOG *************************************************************/

#if WIP_FWD_LOG
void
fwdUninit(void)
{
    if (NULL == logfile)
        return;

    logfileClose(logfile);

    logfile = NULL;
}

void
fwdLogRotate(void)
{
    if (logfile)
        logfileRotate(logfile);
}

static void
FwdState::log()
{
    if (NULL == logfile)
        return;

    logfilePrintf(logfile, "%9d.%03d %03d %s %s\n",
                  (int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  last_status,
                  RequestMethodStr(request->method),
                  request->canonical);
}

void
FwdState::status(http_status s)
{
    last_status = s;
}

#endif
