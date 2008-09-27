
/*
 * $Id: forward.cc,v 1.168.2.2 2008/02/27 10:42:23 amosjeffries Exp $
 *
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
#include "forward.h"
#include "ACLChecklist.h"
#include "ACL.h"
#include "CacheManager.h"
#include "event.h"
#include "errorpage.h"
#include "fde.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "pconn.h"
#include "SquidTime.h"
#include "Store.h"

#if LINUX_TPROXY
#include <linux/netfilter_ipv4/ip_tproxy.h>
#endif

static PSC fwdStartCompleteWrapper;
static PF fwdServerClosedWrapper;
#if USE_SSL
static PF fwdNegotiateSSLWrapper;
#endif
static PF fwdConnectTimeoutWrapper;
static EVH fwdConnectStartWrapper;
static CNCB fwdConnectDoneWrapper;

static OBJH fwdStats;
static void fwdServerFree(FwdServer * fs);

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

    if (fwd->server_fd >= 0) {
        comm_close(fwd->server_fd);
        fwd->server_fd = -1;
    }

    fwd->self = NULL;
}

/**** PUBLIC INTERFACE ********************************************************/

FwdState::FwdState(int fd, StoreEntry * e, HttpRequest * r)
{
    entry = e;
    client_fd = fd;
    server_fd = -1;
    request = HTTPMSGLOCK(r);
    start_t = squid_curtime;

    e->lock()

    ;
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
    peerSelect(request, entry, fwdStartCompleteWrapper, this);

    // TODO: set self _after_ the peer is selected because we do not need
    // self until we start talking to some Server.
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

    serversFree(&servers);

    HTTPMSGUNLOCK(request);

    if (err)
        errorStateFree(err);

    entry->unregisterAbort();

    entry->unlock();

    entry = NULL;

    int fd = server_fd;

    if (fd > -1) {
        server_fd = -1;
        comm_remove_close_handler(fd, fwdServerClosedWrapper, this);
        debugs(17, 3, "fwdStateFree: closing FD " << fd);
        comm_close(fd);
    }

    debugs(17, 3, HERE << "FwdState destructor done");
}

/*
 * This is the entry point for client-side to start forwarding
 * a transaction.  It is a static method that may or may not
 * allocate a FwdState.
 */
void
FwdState::fwdStart(int client_fd, StoreEntry *entry, HttpRequest *request)
{
    /*
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if (request->client_addr.s_addr != no_addr.s_addr && request->protocol != PROTO_INTERNAL && request->protocol != PROTO_CACHEOBJ) {
        /*
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         */
        ACLChecklist ch;
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        ch.my_port = request->my_port;
        ch.request = HTTPMSGLOCK(request);
        ch.accessList = cbdataReference(Config.accessList.miss);
        /* cbdataReferenceDone() happens in either fastCheck() or ~ACLCheckList */
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

    debugs(17, 3, "FwdState::start() '" << entry->url() << "'");
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
        cachemgrStart(client_fd, request, entry);
        return;

    case PROTO_URN:
        urnStart(request, entry);
        return;

    default:
        FwdState::Pointer fwd = new FwdState(client_fd, entry, request);
#if LINUX_TPROXY
        /* If we need to transparently proxy the request
         * then we need the client source address and port */
        fwd->src.sin_family = AF_INET;
        fwd->src.sin_addr = request->client_addr;
        fwd->src.sin_port = request->client_port;
#endif

        fwd->start(fwd);
        return;
    }

    /* NOTREACHED */
}

void
FwdState::fail(ErrorState * errorState)
{
    debugs(17, 3, "fwdFail: " << err_type_str[errorState->type] << " \"" << httpStatusString(errorState->httpStatus) << "\"\n\t" << entry->url()  );

    if (err)
        errorStateFree(err);

    err = errorState;

    if (!errorState->request)
        errorState->request = HTTPMSGLOCK(request);
}

/*
 * Frees fwdState without closing FD or generating an abort
 */
void
FwdState::unregister(int fd)
{
    debugs(17, 3, "fwdUnregister: " << entry->url()  );
    assert(fd == server_fd);
    assert(fd > -1);
    comm_remove_close_handler(fd, fwdServerClosedWrapper, this);
    server_fd = -1;
}

/*
 * server-side modules call fwdComplete() when they are done
 * downloading an object.  Then, we either 1) re-forward the
 * request somewhere else if needed, or 2) call storeComplete()
 * to finish it off
 */
void
FwdState::complete()
{
    StoreEntry *e = entry;
    assert(entry->store_status == STORE_PENDING);
    debugs(17, 3, "fwdComplete: " << e->url() << "\n\tstatus " << entry->getReply()->sline.status  );
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    logReplyStatus(n_tries, entry->getReply()->sline.status);

    if (reforward()) {
        debugs(17, 3, "fwdComplete: re-forwarding " << entry->getReply()->sline.status << " " << e->url());

        if (server_fd > -1)
            unregister(server_fd);

        e->reset();

        startComplete(servers);
    } else {
        debugs(17, 3, "fwdComplete: not re-forwarding status " << entry->getReply()->sline.status);
        EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
        entry->complete();

        if (server_fd < 0)
            completed();

        self = NULL; // refcounted
    }
}


/**** CALLBACK WRAPPERS ************************************************************/

static void
fwdStartCompleteWrapper(FwdServer * servers, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->startComplete(servers);
}

static void
fwdServerClosedWrapper(int fd, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->serverClosed(fd);
}

static void
fwdConnectStartWrapper(void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->connectStart();
}

#if USE_SSL
static void
fwdNegotiateSSLWrapper(int fd, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->negotiateSSL(fd);
}

#endif

static void
fwdConnectDoneWrapper(int server_fd, comm_err_t status, int xerrno, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->connectDone(server_fd, status, xerrno);
}

static void
fwdConnectTimeoutWrapper(int fd, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->connectTimeout(fd);
}

/*
 * Accounts for closed persistent connections
 */
static void
fwdPeerClosed(int fd, void *data)
{
    peer *p = (peer *)data;
    p->stats.conn_open--;
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
    switch (request->method) {
        /* 9.1.1 Safe Methods */

    case METHOD_GET:

    case METHOD_HEAD:
        /* 9.1.2 Indepontent Methods */

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
    debugs(17, 2, "fwdServerClosed: FD " << fd << " " << entry->url());
    assert(server_fd == fd);
    server_fd = -1;

    retryOrBail();
}

void
FwdState::retryOrBail() {
    if (!self) { // we have aborted before the server called us back
        debugs(17, 5, HERE << "not retrying because of earlier abort");
        // we will be destroyed when the server clears its Pointer to us
        return;
    }

    if (checkRetry()) {
        int originserver = (servers->_peer == NULL);
        debugs(17, 3, "fwdServerClosed: re-forwarding (" << n_tries << " tries, " << (squid_curtime - start_t) << " secs)");

        if (servers->next) {
            /* use next, or cycle if origin server isn't last */
            FwdServer *fs = servers;
            FwdServer **T, *T2 = NULL;
            servers = fs->next;

            for (T = &servers; *T; T2 = *T, T = &(*T)->next)

                ;
            if (T2 && T2->_peer) {
                /* cycle */
                *T = fs;
                fs->next = NULL;
            } else {
                /* Use next. The last "direct" entry is retried multiple times */
                servers = fs->next;
                fwdServerFree(fs);
                originserver = 0;
            }
        }

        /* use eventAdd to break potential call sequence loops and to slow things down a little */
        eventAdd("fwdConnectStart", fwdConnectStartWrapper, this, originserver ? 0.05 : 0.005, 0);

        return;
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
    debugs(17, 2, "handleUnregisteredServerEnd: self=" << self <<
        " err=" << err << ' ' << entry->url());
    assert(server_fd < 0);
    retryOrBail();
}

#if USE_SSL
void
FwdState::negotiateSSL(int fd)
{
    FwdServer *fs = servers;
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
            ErrorState *anErr = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
#ifdef EPROTO

            anErr->xerrno = EPROTO;
#else

            anErr->xerrno = EACCES;
#endif

            fail(anErr);

            if (fs->_peer) {
                peerConnectFailed(fs->_peer);
                fs->_peer->stats.conn_open--;
            }

            comm_close(fd);
            return;
        }
    }

    if (fs->_peer && !SSL_session_reused(ssl)) {
        if (fs->_peer->sslSession)
            SSL_SESSION_free(fs->_peer->sslSession);

        fs->_peer->sslSession = SSL_get1_session(ssl);
    }

    dispatch();
}

void
FwdState::initiateSSL()
{
    FwdServer *fs = servers;
    int fd = server_fd;
    SSL *ssl;
    SSL_CTX *sslContext = NULL;
    peer *peer = fs->_peer;

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
        SSL_set_ex_data(ssl, ssl_ex_index_server, request->host);
    }

    fd_table[fd].ssl = ssl;
    fd_table[fd].read_method = &ssl_read_method;
    fd_table[fd].write_method = &ssl_write_method;
    negotiateSSL(fd);
}

#endif

void
FwdState::connectDone(int aServerFD, comm_err_t status, int xerrno)
{
    FwdServer *fs = servers;
    assert(server_fd == aServerFD);

    if (Config.onoff.log_ip_on_direct && status != COMM_ERR_DNS && fs->code == HIER_DIRECT)
        updateHierarchyInfo();

    if (status == COMM_ERR_DNS) {
        /*
         * Only set the dont_retry flag if the DNS lookup fails on
         * a direct connection.  If DNS lookup fails when trying
         * a neighbor cache, we may want to retry another option.
         */

        if (NULL == fs->_peer)
            flags.dont_retry = 1;

        debugs(17, 4, "fwdConnectDone: Unknown host: " << request->host);

        ErrorState *anErr = errorCon(ERR_DNS_FAIL, HTTP_SERVICE_UNAVAILABLE, request);

        anErr->dnsserver_msg = xstrdup(dns_error_message_safe());

        fail(anErr);

        comm_close(server_fd);
    } else if (status != COMM_OK) {
        assert(fs);
        ErrorState *anErr = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE, request);
        anErr->xerrno = xerrno;

        fail(anErr);

        if (fs->_peer)
            peerConnectFailed(fs->_peer);

        comm_close(server_fd);
    } else {
        debugs(17, 3, "fwdConnectDone: FD " << server_fd << ": '" << entry->url() << "'" );

        if (fs->_peer)
            peerConnectSucceded(fs->_peer);

#if USE_SSL

        if ((fs->_peer && fs->_peer->use_ssl) ||
                (!fs->_peer && request->protocol == PROTO_HTTPS)) {
            initiateSSL();
            return;
        }

#endif
        dispatch();
    }
}

void
FwdState::connectTimeout(int fd)
{
    FwdServer *fs = servers;

    debugs(17, 2, "fwdConnectTimeout: FD " << fd << ": '" << entry->url() << "'" );
    assert(fd == server_fd);

    if (Config.onoff.log_ip_on_direct && fs->code == HIER_DIRECT && fd_table[fd].ipaddr[0])
        updateHierarchyInfo();

    if (entry->isEmpty()) {
        ErrorState *anErr = errorCon(ERR_CONNECT_FAIL, HTTP_GATEWAY_TIMEOUT, request);
        anErr->xerrno = ETIMEDOUT;
        fail(anErr);
        /*
         * This marks the peer DOWN ... 
         */

        if (servers)
            if (servers->_peer)
                peerConnectFailed(servers->_peer);
    }

    comm_close(fd);
}

void
FwdState::connectStart()
{
    const char *url = entry->url();
    int fd = -1;
    FwdServer *fs = servers;
    const char *host;
    unsigned short port;
    const char *domain = NULL;
    int ctimeout;
    int ftimeout = Config.Timeout.forward - (squid_curtime - start_t);
#if LINUX_TPROXY

    struct in_tproxy itp;
#endif

    struct IN_ADDR outgoing;
    unsigned short tos;

    struct IN_ADDR *client_addr = NULL;
    assert(fs);
    assert(server_fd == -1);
    debugs(17, 3, "fwdConnectStart: " << url);

    if (fs->_peer) {
        host = fs->_peer->host;
        port = fs->_peer->http_port;
        ctimeout = fs->_peer->connect_timeout > 0 ? fs->_peer->connect_timeout
                   : Config.Timeout.peer_connect;

        if (fs->_peer->options.originserver)
            domain = request->host;
    } else {
        host = request->host;
        port = request->port;
        ctimeout = Config.Timeout.connect;
    }

#if LINUX_TPROXY
    if (request->flags.tproxy)
        client_addr = &request->client_addr;

#endif

    if (ftimeout < 0)
        ftimeout = 5;

    if (ftimeout < ctimeout)
        ctimeout = ftimeout;

    fd = fwdPconnPool->pop(host, port, domain, client_addr, checkRetriable());
    if (fd >= 0) {
        debugs(17, 3, "fwdConnectStart: reusing pconn FD " << fd);
        server_fd = fd;
        n_tries++;

        if (!fs->_peer)
            origin_tries++;

        updateHierarchyInfo();

        comm_add_close_handler(fd, fwdServerClosedWrapper, this);

        dispatch();

        return;
    }

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();

#endif

    outgoing = getOutgoingAddr(request);

    tos = getOutgoingTOS(request);

    debugs(17, 3, "fwdConnectStart: got addr " << inet_ntoa(outgoing) << ", tos " << tos);

    fd = comm_openex(SOCK_STREAM,
                     IPPROTO_TCP,
                     outgoing,
                     0,
                     COMM_NONBLOCKING,
                     tos,
                     url);

    if (fd < 0) {
        debugs(50, 4, "fwdConnectStart: " << xstrerror());
        ErrorState *anErr = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        anErr->xerrno = errno;
        fail(anErr);
        self = NULL;	// refcounted
        return;
    }

    server_fd = fd;
    n_tries++;

    if (!fs->_peer)
        origin_tries++;

    /*
     * stats.conn_open is used to account for the number of
     * connections that we have open to the peer, so we can limit
     * based on the max-conn option.  We need to increment here,
     * even if the connection may fail.
     */

    if (fs->_peer) {
        fs->_peer->stats.conn_open++;
        comm_add_close_handler(fd, fwdPeerClosed, fs->_peer);
    }

    comm_add_close_handler(fd, fwdServerClosedWrapper, this);

    commSetTimeout(fd, ctimeout, fwdConnectTimeoutWrapper, this);

    if (!fs->_peer) {
#if LINUX_TPROXY

        if (request->flags.tproxy) {
            itp.v.addr.faddr.s_addr = src.sin_addr.s_addr;
            itp.v.addr.fport = 0;

            /* If these syscalls fail then we just fallback to connecting
             * normally by simply ignoring the errors...
             */
            itp.op = TPROXY_ASSIGN;

            if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp, sizeof(itp)) == -1) {
                debugs(20, 1, "tproxy ip=" << inet_ntoa(itp.v.addr.faddr) <<
                       ",0x" << std::hex << itp.v.addr.faddr.s_addr << std::dec <<
                       ",port=" << itp.v.addr.fport << " ERROR ASSIGN");

                request->flags.tproxy = 0;
            } else {
                itp.op = TPROXY_FLAGS;
                itp.v.flags = ITP_CONNECT;

                if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp, sizeof(itp)) == -1) {
                    debugs(20, 1, "tproxy ip=" << std::hex <<
                           itp.v.addr.faddr.s_addr << std::dec << ",port=" <<
                           itp.v.addr.fport << " ERROR CONNECT");

                    request->flags.tproxy = 0;
                }
            }
        }

#endif
    }

    updateHierarchyInfo();
    commConnectStart(fd, host, port, fwdConnectDoneWrapper, this);
}

void
FwdState::startComplete(FwdServer * theServers)
{
    debugs(17, 3, "fwdStartComplete: " << entry->url()  );

    if (theServers != NULL) {
        servers = theServers;
        connectStart();
    } else {
        startFail();
    }
}

void
FwdState::startFail()
{
    debugs(17, 3, "fwdStartFail: " << entry->url()  );
    ErrorState *anErr = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE, request);
    anErr->xerrno = errno;
    fail(anErr);
    self = NULL;	// refcounted
}

void
FwdState::dispatch()
{
    peer *p = NULL;
    debugs(17, 3, "fwdDispatch: FD " << client_fd << ": Fetching '" << RequestMethodStr[request->method] << " " << entry->url() << "'" );
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(server_fd > -1);

    fd_note(server_fd, entry->url());

    fd_table[server_fd].noteUse(fwdPconnPool);

    /*assert(!EBIT_TEST(entry->flags, ENTRY_DISPATCHED)); */
    assert(entry->ping_status != PING_WAITING);

    assert(entry->lock_count);

    EBIT_SET(entry->flags, ENTRY_DISPATCHED);

    netdbPingSite(request->host);

    if (servers && (p = servers->_peer)) {
        p->stats.fetches++;
        request->peer_login = p->login;
        request->peer_domain = p->domain;
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
            comm_close(server_fd);
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
    FwdServer *fs = servers;
    http_status s;
    assert(e->store_status == STORE_PENDING);
    assert(e->mem_obj);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif

    debugs(17, 3, "fwdReforward: " << e->url() << "?" );

    if (!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
        debugs(17, 3, "fwdReforward: No, ENTRY_FWD_HDR_WAIT isn't set");
        return 0;
    }

    if (n_tries > 9)
        return 0;

    if (origin_tries > 1)
        return 0;

    if (request->bodyNibbled())
        return 0;

    assert(fs);

    servers = fs->next;

    fwdServerFree(fs);

    if (servers == NULL) {
        debugs(17, 3, "fwdReforward: No forward-servers left");
        return 0;
    }

    s = e->getReply()->sline.status;
    debugs(17, 3, "fwdReforward: status " << s);
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

void

FwdState::pconnPush(int fd, const char *host, int port, const char *domain, struct IN_ADDR *client_addr)
{
    fwdPconnPool->push(fd, host, port, domain, client_addr);
}

void
FwdState::initModule()
{
    memDataInit(MEM_FWD_SERVER, "FwdServer", sizeof(FwdServer), 0);

#if WIP_FWD_LOG

    if (logfile)
        (void) 0;
    else if (NULL == Config.Log.forward)
        (void) 0;
    else
        logfile = logfileOpen(Config.Log.forward, 0, 1);

#endif
}

void
FwdState::RegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("forward",
                           "Request Forwarding Statistics",
                           fwdStats, 0, 1);
}

void
FwdState::logReplyStatus(int tries, http_status status)
{
    if (status > HTTP_INVALID_HEADER)
        return;

    assert(tries);

    tries--;

    if (tries > MAX_FWD_STATS_IDX)
        tries = MAX_FWD_STATS_IDX;

    FwdReplyCodes[tries][status]++;
}

void
FwdState::serversFree(FwdServer ** FSVR)
{
    FwdServer *fs;

    while ((fs = *FSVR)) {
        *FSVR = fs->next;
        fwdServerFree(fs);
    }
}

// updates HierarchyLogEntry, guessing nextHop and its format
void
FwdState::updateHierarchyInfo()
{
    assert(request);

    FwdServer *fs = servers;
    assert(fs);

    const char *nextHop = NULL;

    if (fs->_peer) {
        // went to peer, log peer host name
        nextHop = fs->_peer->name;
    } else {
        // went DIRECT, must honor log_ip_on_direct

        // XXX: or should we use request->host_addr here? how?
        assert(server_fd >= 0);
        nextHop = fd_table[server_fd].ipaddr;
        if (!Config.onoff.log_ip_on_direct || !nextHop[0])
            nextHop = request->host; // domain name
    }

    assert(nextHop);
    hierarchyNote(&request->hier, fs->code, nextHop);
}


/**** PRIVATE NON-MEMBER FUNCTIONS ********************************************/

static void
fwdServerFree(FwdServer * fs)
{
    cbdataReferenceDone(fs->_peer);
    memFree(fs, MEM_FWD_SERVER);
}

static struct IN_ADDR
            aclMapAddr(acl_address * head, ACLChecklist * ch)
{
    acl_address *l;

    struct IN_ADDR addr;

    for (l = head; l; l = l->next)
    {
        if (ch->matchAclListFast(l->aclList))
            return l->addr;
    }

    addr.s_addr = INADDR_ANY;
    return addr;
}

/*
 * DPW 2007-05-19
 * Formerly static, but now used by client_side_request.cc
 */
int
aclMapTOS(acl_tos * head, ACLChecklist * ch)
{
    acl_tos *l;

    for (l = head; l; l = l->next) {
        if (ch->matchAclListFast(l->aclList))
            return l->tos;
    }

    return 0;
}

struct IN_ADDR
            getOutgoingAddr(HttpRequest * request)
{
    ACLChecklist ch;

    if (request)
    {
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        ch.my_port = request->my_port;
        ch.request = HTTPMSGLOCK(request);
    }

    return aclMapAddr(Config.accessList.outgoing_address, &ch);
}

unsigned long
getOutgoingTOS(HttpRequest * request)
{
    ACLChecklist ch;

    if (request) {
        ch.src_addr = request->client_addr;
        ch.my_addr = request->my_addr;
        ch.my_port = request->my_port;
        ch.request = HTTPMSGLOCK(request);
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
                  RequestMethodStr[request->method],
                  request->canonical);
}

void
FwdState::status(http_status s)
{
    last_status = s;
}

#endif
