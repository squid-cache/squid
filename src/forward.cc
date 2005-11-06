
/*
 * $Id: forward.cc,v 1.130 2005/11/06 11:14:27 serassio Exp $
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
#include "Store.h"
#include "HttpRequest.h"
#include "fde.h"
#include "MemObject.h"
#include "ACLChecklist.h"
#include "ACL.h"
#include "HttpReply.h"

static PSC fwdStartComplete;
static void fwdDispatch(FwdState *);
static void fwdConnectStart(void *);	/* should be same as EVH */
static void fwdStateFree(FwdState * fwdState);
static PF fwdConnectTimeout;
static PF fwdServerClosed;
static PF fwdPeerClosed;
static CNCB fwdConnectDone;
static int fwdCheckRetry(FwdState * fwdState);
static int fwdReforward(FwdState *);
static void fwdStartFail(FwdState *);
static void fwdLogReplyStatus(int tries, http_status status);
static OBJH fwdStats;
static STABH fwdAbort;
static peer *fwdStateServerPeer(FwdState *);

#define MAX_FWD_STATS_IDX 9
static int FwdReplyCodes[MAX_FWD_STATS_IDX + 1][HTTP_INVALID_HEADER + 1];

#if WIP_FWD_LOG
static void fwdLog(FwdState * fwdState);
static Logfile *logfile = NULL;
#endif

static peer *
fwdStateServerPeer(FwdState * fwdState)
{
    if (NULL == fwdState)
        return NULL;

    if (NULL == fwdState->servers)
        return NULL;

    return fwdState->servers->_peer;
}

static void
fwdServerFree(FwdServer * fs)
{
    cbdataReferenceDone(fs->_peer);
    memFree(fs, MEM_FWD_SERVER);
}

static void
fwdStateFree(FwdState * fwdState)
{
    StoreEntry *e = fwdState->entry;
    int sfd;
    peer *p;
    debug(17, 3) ("fwdStateFree: %p\n", fwdState);
    assert(e->mem_obj);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif
#if WIP_FWD_LOG

    fwdLog(fwdState);
#endif

    if (e->store_status == STORE_PENDING) {
        if (e->isEmpty()) {
            assert(fwdState->err);
            errorAppendEntry(e, fwdState->err);
            fwdState->err = NULL;
        } else {
            EBIT_CLR(e->flags, ENTRY_FWD_HDR_WAIT);
            e->complete();
            storeReleaseRequest(e);
        }
    }

    if (storePendingNClients(e) > 0)
        assert(!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT));

    p = fwdStateServerPeer(fwdState);

    fwdServersFree(&fwdState->servers);

    requestUnlink(fwdState->request);

    fwdState->request = NULL;

    if (fwdState->err)
        errorStateFree(fwdState->err);

    storeUnregisterAbort(e);

    storeUnlockObject(e);

    fwdState->entry = NULL;

    sfd = fwdState->server_fd;

    if (sfd > -1) {
        comm_remove_close_handler(sfd, fwdServerClosed, fwdState);
        fwdState->server_fd = -1;
        debug(17, 3) ("fwdStateFree: closing FD %d\n", sfd);
        comm_close(sfd);
    }

    cbdataFree(fwdState);
}

static int
fwdCheckRetry(FwdState * fwdState)
{
    if (shutting_down)
        return 0;

    if (fwdState->entry->store_status != STORE_PENDING)
        return 0;

    if (!fwdState->entry->isEmpty())
        return 0;

    if (fwdState->n_tries > 10)
        return 0;

    if (fwdState->origin_tries > 2)
        return 0;

    if (squid_curtime - fwdState->start > Config.Timeout.forward)
        return 0;

    if (fwdState->flags.dont_retry)
        return 0;

    if (fwdState->request->flags.body_sent)
        return 0;

    return 1;
}

static int
fwdCheckRetriable(FwdState * fwdState)
{
    /* If there is a request body then Squid can only try once
     * even if the method is indempotent
     */

    if (fwdState->request->body_connection.getRaw() != NULL)
        return 0;

    /* RFC2616 9.1 Safe and Idempotent Methods */
    switch (fwdState->request->method) {
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
        return 0;
    }

    return 1;
}

static void
fwdServerClosed(int fd, void *data)
{
    FwdState *fwdState = (FwdState *)data;
    debug(17, 2) ("fwdServerClosed: FD %d %s\n", fd, storeUrl(fwdState->entry));
    assert(fwdState->server_fd == fd);
    fwdState->server_fd = -1;

    if (fwdCheckRetry(fwdState)) {
        int originserver = (fwdState->servers->_peer == NULL);
        debug(17, 3) ("fwdServerClosed: re-forwarding (%d tries, %d secs)\n",
                      fwdState->n_tries,
                      (int) (squid_curtime - fwdState->start));

        if (fwdState->servers->next) {
            /* use next, or cycle if origin server isn't last */
            FwdServer *fs = fwdState->servers;
            FwdServer **T, *T2 = NULL;
            fwdState->servers = fs->next;

            for (T = &fwdState->servers; *T; T2 = *T, T = &(*T)->next)

                ;
            if (T2 && T2->_peer) {
                /* cycle */
                *T = fs;
                fs->next = NULL;
            } else {
                /* Use next. The last "direct" entry is retried multiple times */
                fwdState->servers = fs->next;
                fwdServerFree(fs);
                originserver = 0;
            }
        }

        /* use eventAdd to break potential call sequence loops and to slow things down a little */
        eventAdd("fwdConnectStart", fwdConnectStart, fwdState, originserver ? 0.05 : 0.005, 0);

        return;
    }

    if (!fwdState->err && shutting_down) {
        fwdState->err =errorCon(ERR_SHUTTING_DOWN, HTTP_SERVICE_UNAVAILABLE);
        fwdState->err->request = requestLink(fwdState->request);
    }

    fwdStateFree(fwdState);
}

#if USE_SSL
static void
fwdNegotiateSSL(int fd, void *data)
{
    FwdState *fwdState = (FwdState *)data;
    FwdServer *fs = fwdState->servers;
    SSL *ssl = fd_table[fd].ssl;
    int ret;
    ErrorState *err;
    HttpRequest *request = fwdState->request;

    if ((ret = SSL_connect(ssl)) <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);

        switch (ssl_error) {

        case SSL_ERROR_WANT_READ:
            commSetSelect(fd, COMM_SELECT_READ, fwdNegotiateSSL, fwdState, 0);
            return;

        case SSL_ERROR_WANT_WRITE:
            commSetSelect(fd, COMM_SELECT_WRITE, fwdNegotiateSSL, fwdState, 0);
            return;

        default:
            debug(81, 1) ("fwdNegotiateSSL: Error negotiating SSL connection on FD %d: %s (%d/%d/%d)\n", fd, ERR_error_string(ERR_get_error(), NULL), ssl_error, ret, errno);
            err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
#ifdef EPROTO

            err->xerrno = EPROTO;
#else

            err->xerrno = EACCES;
#endif

            if (fs->_peer) {
                err->host = xstrdup(fs->_peer->host);
                err->port = fs->_peer->http_port;
            } else {
                err->host = xstrdup(request->host);
                err->port = request->port;
            }

            err->request = requestLink(request);
            fwdFail(fwdState, err);

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

    fwdDispatch(fwdState);
}

static void
fwdInitiateSSL(FwdState * fwdState)
{
    FwdServer *fs = fwdState->servers;
    int fd = fwdState->server_fd;
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
        ErrorState *err;
        debug(83, 1) ("fwdInitiateSSL: Error allocating handle: %s\n",
                      ERR_error_string(ERR_get_error(), NULL));
        err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
        err->xerrno = errno;
        err->request = requestLink(fwdState->request);
        fwdFail(fwdState, err);
        fwdStateFree(fwdState);
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
        SSL_set_ex_data(ssl, ssl_ex_index_server, fwdState->request->host);
    }

    fd_table[fd].ssl = ssl;
    fd_table[fd].read_method = &ssl_read_method;
    fd_table[fd].write_method = &ssl_write_method;
    fwdNegotiateSSL(fd, fwdState);
}

#endif

static void
fwdConnectDone(int server_fd, comm_err_t status, int xerrno, void *data)
{
    FwdState *fwdState = (FwdState *)data;
    FwdServer *fs = fwdState->servers;
    ErrorState *err;
    HttpRequest *request = fwdState->request;
    assert(fwdState->server_fd == server_fd);

    if (status == COMM_ERR_DNS) {
        /*
         * Only set the dont_retry flag if the DNS lookup fails on
         * a direct connection.  If DNS lookup fails when trying
         * a neighbor cache, we may want to retry another option.
         */

        if (NULL == fs->_peer)
            fwdState->flags.dont_retry = 1;

        debug(17, 4) ("fwdConnectDone: Unknown host: %s\n",
                      request->host);

        err = errorCon(ERR_DNS_FAIL, HTTP_SERVICE_UNAVAILABLE);

        err->dnsserver_msg = xstrdup(dns_error_message);

        fwdFail(fwdState, err);

        comm_close(server_fd);
    } else if (status != COMM_OK) {
        assert(fs);
        err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
        err->xerrno = xerrno;

        if (fs->_peer) {
            err->host = xstrdup(fs->_peer->host);
            err->port = fs->_peer->http_port;
        } else {
            err->host = xstrdup(request->host);
            err->port = request->port;
        }

        fwdFail(fwdState, err);

        if (fs->_peer)
            peerConnectFailed(fs->_peer);

        comm_close(server_fd);
    } else {
        debug(17, 3) ("fwdConnectDone: FD %d: '%s'\n", server_fd, storeUrl(fwdState->entry));

        if (fs->_peer)
            peerConnectSucceded(fs->_peer);

#if USE_SSL

        if ((fs->_peer && fs->_peer->use_ssl) ||
                (!fs->_peer && request->protocol == PROTO_HTTPS)) {
            fwdInitiateSSL(fwdState);
            return;
        }

#endif
        fwdDispatch(fwdState);
    }
}

static void
fwdConnectTimeout(int fd, void *data)
{
    FwdState *fwdState = (FwdState *)data;
    StoreEntry *entry = fwdState->entry;
    ErrorState *err;
    debug(17, 2) ("fwdConnectTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    assert(fd == fwdState->server_fd);

    if (entry->isEmpty()) {
        err = errorCon(ERR_CONNECT_FAIL, HTTP_GATEWAY_TIMEOUT);
        err->xerrno = ETIMEDOUT;
        fwdFail(fwdState, err);
        /*
         * This marks the peer DOWN ... 
         */

        if (fwdState->servers)
            if (fwdState->servers->_peer)
                peerConnectFailed(fwdState->servers->_peer);
    }

    comm_close(fd);
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

static int
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
        ch.request = requestLink(request);
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
        ch.request = requestLink(request);
    }

    return aclMapTOS(Config.accessList.outgoing_tos, &ch);
}

static void
fwdConnectStart(void *data)
{
    FwdState *fwdState = (FwdState *)data;
    const char *url = storeUrl(fwdState->entry);
    int fd = -1;
    ErrorState *err;
    FwdServer *fs = fwdState->servers;
    const char *host;
    unsigned short port;
    const char *domain = NULL;
    int ctimeout;
    int ftimeout = Config.Timeout.forward - (squid_curtime - fwdState->start);

    struct IN_ADDR outgoing;
    unsigned short tos;
    assert(fs);
    assert(fwdState->server_fd == -1);
    debug(17, 3) ("fwdConnectStart: %s\n", url);

    if (fs->_peer) {
        host = fs->_peer->host;
        port = fs->_peer->http_port;
        ctimeout = fs->_peer->connect_timeout > 0 ? fs->_peer->connect_timeout
                   : Config.Timeout.peer_connect;

        if (fs->_peer->options.originserver)
            domain = fwdState->request->host;
    } else {
        host = fwdState->request->host;
        port = fwdState->request->port;
        ctimeout = Config.Timeout.connect;
    }

    if (ftimeout < 0)
        ftimeout = 5;

    if (ftimeout < ctimeout)
        ctimeout = ftimeout;

    if ((fd = pconnPop(host, port, domain)) >= 0) {
        if (fwdCheckRetriable(fwdState)) {
            debug(17, 3) ("fwdConnectStart: reusing pconn FD %d\n", fd);
            fwdState->server_fd = fd;
            fwdState->n_tries++;

            if (!fs->_peer)
                fwdState->origin_tries++;

            comm_add_close_handler(fd, fwdServerClosed, fwdState);

            fwdDispatch(fwdState);

            return;
        } else {
            /* Discard the persistent connection to not cause
             * an imbalance in number of connections open if there
             * is a lot of POST requests
             */
            comm_close(fd);
        }
    }

#if URL_CHECKSUM_DEBUG
    fwdState->entry->mem_obj->checkUrlChecksum();

#endif

    outgoing = getOutgoingAddr(fwdState->request);

    tos = getOutgoingTOS(fwdState->request);

    debug(17, 3) ("fwdConnectStart: got addr %s, tos %d\n",
                  inet_ntoa(outgoing), tos);

    fd = comm_openex(SOCK_STREAM,
                     IPPROTO_TCP,
                     outgoing,
                     0,
                     COMM_NONBLOCKING,
                     tos,
                     url);

    if (fd < 0) {
        debug(50, 4) ("fwdConnectStart: %s\n", xstrerror());
        err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
        err->xerrno = errno;
        fwdFail(fwdState, err);
        fwdStateFree(fwdState);
        return;
    }

    fwdState->server_fd = fd;
    fwdState->n_tries++;

    if (!fs->_peer)
        fwdState->origin_tries++;

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

    comm_add_close_handler(fd, fwdServerClosed, fwdState);

    commSetTimeout(fd,
                   ctimeout,
                   fwdConnectTimeout,
                   fwdState);

    commConnectStart(fd, host, port, fwdConnectDone, fwdState);
}

static void
fwdStartComplete(FwdServer * servers, void *data)
{
    FwdState *fwdState = (FwdState *)data;
    debug(17, 3) ("fwdStartComplete: %s\n", storeUrl(fwdState->entry));

    if (servers != NULL) {
        fwdState->servers = servers;
        fwdConnectStart(fwdState);
    } else {
        fwdStartFail(fwdState);
    }
}

static void
fwdStartFail(FwdState * fwdState)
{
    ErrorState *err;
    debug(17, 3) ("fwdStartFail: %s\n", storeUrl(fwdState->entry));
    err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE);
    err->xerrno = errno;
    fwdFail(fwdState, err);
    fwdStateFree(fwdState);
}

static void
fwdDispatch(FwdState * fwdState)
{
    peer *p = NULL;
    HttpRequest *request = fwdState->request;
    StoreEntry *entry = fwdState->entry;
    ErrorState *err;
    FwdServer *fs = fwdState->servers;
    int server_fd = fwdState->server_fd;
    debug(17, 3) ("fwdDispatch: FD %d: Fetching '%s %s'\n",
                  fwdState->client_fd,
                  RequestMethodStr[request->method],
                  storeUrl(entry));
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(server_fd > -1);

    if (fs->_peer)
        hierarchyNote(&fwdState->request->hier, fs->code, fs->_peer->host);
    else if (Config.onoff.log_ip_on_direct)
        hierarchyNote(&fwdState->request->hier, fs->code, fd_table[server_fd].ipaddr);
    else
        hierarchyNote(&fwdState->request->hier, fs->code, request->host);

    fd_note(server_fd, storeUrl(fwdState->entry));

    fd_table[server_fd].uses++;

    /*assert(!EBIT_TEST(entry->flags, ENTRY_DISPATCHED)); */
    assert(entry->ping_status != PING_WAITING);

    assert(entry->lock_count);

    EBIT_SET(entry->flags, ENTRY_DISPATCHED);

    netdbPingSite(request->host);

    if (fwdState->servers && (p = fwdState->servers->_peer)) {
        p->stats.fetches++;
        fwdState->request->peer_login = p->login;
        fwdState->request->peer_domain = p->domain;
        httpStart(fwdState);
    } else {
        fwdState->request->peer_login = NULL;
        fwdState->request->peer_domain = NULL;

        switch (request->protocol) {
#if USE_SSL

        case PROTO_HTTPS:
            httpStart(fwdState);
            break;
#endif

        case PROTO_HTTP:
            httpStart(fwdState);
            break;

        case PROTO_GOPHER:
            gopherStart(fwdState);
            break;

        case PROTO_FTP:
            ftpStart(fwdState);
            break;

        case PROTO_WAIS:
            waisStart(fwdState);
            break;

        case PROTO_CACHEOBJ:

        case PROTO_INTERNAL:

        case PROTO_URN:
            fatal_dump("Should never get here");
            break;

        case PROTO_WHOIS:
            whoisStart(fwdState);
            break;

        default:
            debug(17, 1) ("fwdDispatch: Cannot retrieve '%s'\n",
                          storeUrl(entry));
            err = errorCon(ERR_UNSUP_REQ, HTTP_BAD_REQUEST);
            fwdFail(fwdState, err);
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
            fwdState->flags.dont_retry = 1;
            comm_close(fwdState->server_fd);
            break;
        }
    }
}

static int
fwdReforward(FwdState * fwdState)
{
    StoreEntry *e = fwdState->entry;
    FwdServer *fs = fwdState->servers;
    http_status s;
    assert(e->store_status == STORE_PENDING);
    assert(e->mem_obj);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif

    debug(17, 3) ("fwdReforward: %s?\n", storeUrl(e));

    if (!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
        debug(17, 3) ("fwdReforward: No, ENTRY_FWD_HDR_WAIT isn't set\n");
        return 0;
    }

    if (fwdState->n_tries > 9)
        return 0;

    if (fwdState->origin_tries > 1)
        return 0;

    if (fwdState->request->flags.body_sent)
        return 0;

    assert(fs);

    fwdState->servers = fs->next;

    fwdServerFree(fs);

    if (fwdState->servers == NULL) {
        debug(17, 3) ("fwdReforward: No forward-servers left\n");
        return 0;
    }

    s = e->getReply()->sline.status;
    debug(17, 3) ("fwdReforward: status %d\n", (int) s);
    return fwdReforwardableStatus(s);
}

/* PUBLIC FUNCTIONS */

void
fwdServersFree(FwdServer ** FSVR)
{
    FwdServer *fs;

    while ((fs = *FSVR)) {
        *FSVR = fs->next;
        fwdServerFree(fs);
    }
}

void
fwdStart(int fd, StoreEntry * e, HttpRequest * r)
{
    FwdState *fwdState;
    int answer;
    ErrorState *err;
    /*
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if (r->client_addr.s_addr != no_addr.s_addr && r->protocol != PROTO_INTERNAL && r->protocol != PROTO_CACHEOBJ) {
        /*
         * Check if this host is allowed to fetch MISSES from us (miss_access)
         */
        ACLChecklist ch;
        ch.src_addr = r->client_addr;
        ch.my_addr = r->my_addr;
        ch.my_port = r->my_port;
        ch.request = requestLink(r);
        ch.accessList = cbdataReference(Config.accessList.miss);
        answer = ch.fastCheck();
        ch.accessList = NULL;

        if (answer == 0) {
            err_type page_id;
            page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName);

            if (page_id == ERR_NONE)
                page_id = ERR_FORWARDING_DENIED;

            err = errorCon(page_id, HTTP_FORBIDDEN);

            err->request = requestLink(r);

            err->src_addr = r->client_addr;

            errorAppendEntry(e, err);

            return;
        }
    }

    debug(17, 3) ("fwdStart: '%s'\n", storeUrl(e));
    e->mem_obj->request = requestLink(r);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif

    if (shutting_down) {
        /* more yuck */
        err = errorCon(ERR_SHUTTING_DOWN, HTTP_SERVICE_UNAVAILABLE);
        err->request = requestLink(r);
        errorAppendEntry(e, err);
        return;
    }

    switch (r->protocol) {
        /*
         * Note, don't create fwdState for these requests
         */

    case PROTO_INTERNAL:
        internalStart(r, e);
        return;

    case PROTO_CACHEOBJ:
        cachemgrStart(fd, r, e);
        return;

    case PROTO_URN:
        urnStart(r, e);
        return;

    default:
        break;
    }

    fwdState = cbdataAlloc(FwdState);
    fwdState->entry = e;
    fwdState->client_fd = fd;
    fwdState->server_fd = -1;
    fwdState->request = requestLink(r);
    fwdState->start = squid_curtime;
    storeLockObject(e);
    EBIT_SET(e->flags, ENTRY_FWD_HDR_WAIT);
    storeRegisterAbort(e, fwdAbort, fwdState);
    peerSelect(r, e, fwdStartComplete, fwdState);
}

void
fwdFail(FwdState * fwdState, ErrorState * errorState)
{
    debug(17, 3) ("fwdFail: %s \"%s\"\n\t%s\n",
                  err_type_str[errorState->type],
                  httpStatusString(errorState->httpStatus),
                  storeUrl(fwdState->entry));

    if (fwdState->err)
        errorStateFree(fwdState->err);

    fwdState->err = errorState;

    if (!errorState->request)
        errorState->request = requestLink(fwdState->request);
}

/*
 * Called when someone else calls StoreAbort() on this entry
 */
static void
fwdAbort(void *data)
{
    FwdState *fwdState = (FwdState *)data;
    debug(17, 2) ("fwdAbort: %s\n", storeUrl(fwdState->entry));
    fwdStateFree(fwdState);
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

/*
 * Frees fwdState without closing FD or generating an abort
 */
void
fwdUnregister(int fd, FwdState * fwdState)
{
    debug(17, 3) ("fwdUnregister: %s\n", storeUrl(fwdState->entry));
    assert(fd == fwdState->server_fd);
    assert(fd > -1);
    comm_remove_close_handler(fd, fwdServerClosed, fwdState);
    fwdState->server_fd = -1;
}

/*
 * server-side modules call fwdComplete() when they are done
 * downloading an object.  Then, we either 1) re-forward the
 * request somewhere else if needed, or 2) call storeComplete()
 * to finish it off
 */
void
fwdComplete(FwdState * fwdState)
{
    StoreEntry *e = fwdState->entry;
    assert(e->store_status == STORE_PENDING);
    debug(17, 3) ("fwdComplete: %s\n\tstatus %d\n", storeUrl(e),
                  e->getReply()->sline.status);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif

    fwdLogReplyStatus(fwdState->n_tries, e->getReply()->sline.status);

    if (fwdReforward(fwdState)) {
        debug(17, 3) ("fwdComplete: re-forwarding %d %s\n",
                      e->getReply()->sline.status,
                      storeUrl(e));

        if (fwdState->server_fd > -1)
            fwdUnregister(fwdState->server_fd, fwdState);

        storeEntryReset(e);

        fwdStartComplete(fwdState->servers, fwdState);
    } else {
        debug(17, 3) ("fwdComplete: not re-forwarding status %d\n",
                      e->getReply()->sline.status);
        EBIT_CLR(e->flags, ENTRY_FWD_HDR_WAIT);
        e->complete();
        /*
         * If fwdState isn't associated with a server FD, it
         * won't get freed unless we do it here.
         */

        if (fwdState->server_fd < 0)
            fwdStateFree(fwdState);
    }
}

void
fwdInit(void)
{
    cachemgrRegister("forward",
                     "Request Forwarding Statistics",
                     fwdStats, 0, 1);
#if WIP_FWD_LOG

    if (logfile)
        (void) 0;
    else if (NULL == Config.Log.forward)
        (void) 0;
    else
        logfile = logfileOpen(Config.Log.forward, 0, 1);

#endif
}

static void
fwdLogReplyStatus(int tries, http_status status)
{
    if (status > HTTP_INVALID_HEADER)
        return;

    assert(tries);

    tries--;

    if (tries > MAX_FWD_STATS_IDX)
        tries = MAX_FWD_STATS_IDX;

    FwdReplyCodes[tries][status]++;
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

int
fwdReforwardableStatus(http_status s)
{
    switch (s) {

    case HTTP_BAD_GATEWAY:

    case HTTP_GATEWAY_TIMEOUT:
        return 1;

    case HTTP_FORBIDDEN:

    case HTTP_INTERNAL_SERVER_ERROR:

    case HTTP_NOT_IMPLEMENTED:

    case HTTP_SERVICE_UNAVAILABLE:
        return Config.retry.onerror;

    default:
        return 0;
    }

    /* NOTREACHED */
}

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
fwdLog(FwdState * fwdState)
{
    if (NULL == logfile)
        return;

    logfilePrintf(logfile, "%9d.%03d %03d %s %s\n",
                  (int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  fwdState->last_status,
                  RequestMethodStr[fwdState->request->method],
                  fwdState->request->canonical);
}

void
fwdStatus(FwdState * fwdState, http_status s)
{
    fwdState->last_status = s;
}

#endif
