
/*
 * $Id: forward.cc,v 1.27 1998/09/14 21:28:02 wessels Exp $
 *
 * DEBUG: section 17    Request Forwarding
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

static void fwdStartComplete(peer * p, void *data);
static void fwdStartFail(peer * p, void *data);
static void fwdDispatch(FwdState *);
static void fwdConnectStart(FwdState * fwdState);
static void fwdStateFree(FwdState * fwdState);
static PF fwdConnectTimeout;
static PF fwdServerClosed;
static CNCB fwdConnectDone;
static int fwdCheckRetry(FwdState * fwdState);

static void
fwdStateFree(FwdState * fwdState)
{
    FwdServer *s;
    FwdServer *n = fwdState->servers;
    StoreEntry *e = fwdState->entry;
    ErrorState *err;
    int sfd;
    static int loop_detect = 0;
    assert(loop_detect++ == 0);
    assert(e->mem_obj);
    if (e->store_status == STORE_PENDING) {
	if (e->mem_obj->inmem_hi == 0) {
	    assert(fwdState->fail.err_code);
	    err = errorCon(fwdState->fail.err_code, fwdState->fail.http_code);
	    err->request = requestLink(fwdState->request);
	    err->xerrno = fwdState->fail.xerrno;
	    errorAppendEntry(e, err);
	} else {
	    storeAbort(e, 0);
	}
    }
    while ((s = n)) {
	n = s->next;
	xfree(s->host);
	memFree(MEM_FWD_SERVER, s);
    }
    fwdState->servers = NULL;
    requestUnlink(fwdState->request);
    fwdState->request = NULL;
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
    loop_detect--;
}

static int
fwdCheckRetry(FwdState * fwdState)
{
    if (fwdState->entry->store_status != STORE_PENDING)
	return 0;
    if (fwdState->entry->mem_obj->inmem_hi > 0)
	return 0;
    if (fwdState->n_tries > 10)
	return 0;
    if (squid_curtime - fwdState->start > 120)
	return 0;
    if (pumpMethod(fwdState->request->method))
	if (0 == pumpRestart(fwdState->request))
	    return 0;
    return 1;
}

static void
fwdServerClosed(int fd, void *data)
{
    FwdState *fwdState = data;
    debug(17, 3) ("fwdServerClosed: FD %d %s\n", fd, storeUrl(fwdState->entry));
    assert(fwdState->server_fd == fd);
    fwdState->server_fd = -1;
    if (fwdCheckRetry(fwdState)) {
	debug(17, 3) ("fwdServerClosed: re-forwarding (%d tries, %d secs)\n",
	    fwdState->n_tries,
	    (int) (squid_curtime - fwdState->start));
	fwdConnectStart(fwdState);
    } else {
	fwdStateFree(fwdState);
    }
}

static void
fwdConnectDone(int server_fd, int status, void *data)
{
    FwdState *fwdState = data;
    ErrorState *err;
    assert(fwdState->server_fd == server_fd);
    if (status == COMM_ERR_DNS) {
	debug(17, 4) ("fwdConnectDone: Unknown host: %s\n",
	    fwdState->request->host);
	err = errorCon(ERR_DNS_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->request = requestLink(fwdState->request);
	errorAppendEntry(fwdState->entry, err);
	comm_close(server_fd);
    } else if (status != COMM_OK) {
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->host = xstrdup(fwdState->servers->host);
	err->port = fwdState->servers->port;
	err->request = requestLink(fwdState->request);
	errorAppendEntry(fwdState->entry, err);
	assert(fwdState->servers);
	if (fwdState->servers->peer)
	    peerCheckConnectStart(fwdState->servers->peer);
	comm_close(server_fd);
    } else {
	fd_note(server_fd, storeUrl(fwdState->entry));
	fd_table[server_fd].uses++;
	fwdDispatch(fwdState);
    }
}

static void
fwdConnectTimeout(int fd, void *data)
{
    FwdState *fwdState = data;
    StoreEntry *entry = fwdState->entry;
    ErrorState *err;
    debug(17, 3) ("fwdConnectTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    assert(fd == fwdState->server_fd);
    if (entry->mem_obj->inmem_hi == 0) {
	err = errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT);
	err->request = requestLink(fwdState->request);
	errorAppendEntry(entry, err);
    } else {
	storeAbort(entry, 0);
    }
    comm_close(fd);
}

static void
fwdConnectStart(FwdState * fwdState)
{
    const char *url = storeUrl(fwdState->entry);
    int fd;
    ErrorState *err;
    FwdServer *srv = fwdState->servers;
    assert(srv);
    assert(fwdState->server_fd == -1);
    debug(17, 3) ("fwdConnectStart: %s\n", url);
    if ((fd = pconnPop(srv->host, srv->port)) >= 0) {
	debug(17, 3) ("fwdConnectStart: reusing pconn FD %d\n", fd);
	fwdState->server_fd = fd;
	comm_add_close_handler(fd, fwdServerClosed, fwdState);
	fwdConnectDone(fd, COMM_OK, fwdState);
	return;
    }
    fd = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (fd < 0) {
	debug(50, 4) ("fwdConnectStart: %s\n", xstrerror());
	err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->request = requestLink(fwdState->request);
	errorAppendEntry(fwdState->entry, err);
	fwdStateFree(fwdState);
	return;
    }
    fwdState->server_fd = fd;
    fwdState->n_tries++;
    comm_add_close_handler(fd, fwdServerClosed, fwdState);
    commSetTimeout(fd,
	Config.Timeout.connect,
	fwdConnectTimeout,
	fwdState);
    commConnectStart(fd,
	srv->host,
	srv->port,
	fwdConnectDone,
	fwdState);
}

static void
fwdStartComplete(peer * p, void *data)
{
    FwdState *fwdState = data;
    FwdServer *s;
    s = memAllocate(MEM_FWD_SERVER);
    if (NULL != p) {
	s->host = xstrdup(p->host);
	s->port = p->http_port;
	s->peer = p;
    } else {
	s->host = xstrdup(fwdState->request->host);
	s->port = fwdState->request->port;
    }
    fwdState->servers = s;
    fwdConnectStart(fwdState);
}

static void
fwdStartFail(peer * peernotused, void *data)
{
    FwdState *fwdState = data;
    ErrorState *err;
    err = errorCon(ERR_CANNOT_FORWARD, HTTP_SERVICE_UNAVAILABLE);
    err->request = requestLink(fwdState->request);
    errorAppendEntry(fwdState->entry, err);
    fwdStateFree(fwdState);
}

static void
fwdDispatch(FwdState * fwdState)
{
    peer *p;
    request_t *request = fwdState->request;
    StoreEntry *entry = fwdState->entry;
    ErrorState *err;
    debug(17, 5) ("fwdDispatch: FD %d: Fetching '%s %s'\n",
	fwdState->client_fd,
	RequestMethodStr[request->method],
	storeUrl(entry));
    /*assert(!entry->flags.entry_dispatched); */
    assert(entry->ping_status != PING_WAITING);
    assert(entry->lock_count);
    entry->flags.entry_dispatched = 1;
    netdbPingSite(request->host);
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(fwdState->server_fd > -1);
    if (fwdState->servers && (p = fwdState->servers->peer)) {
	p->stats.fetches++;
	httpStart(fwdState, fwdState->server_fd);
    } else {
	switch (request->protocol) {
	case PROTO_HTTP:
	    httpStart(fwdState, fwdState->server_fd);
	    break;
	case PROTO_GOPHER:
	    gopherStart(entry, fwdState->server_fd);
	    break;
	case PROTO_FTP:
	    ftpStart(request, entry, fwdState->server_fd);
	    break;
	case PROTO_WAIS:
	    waisStart(request, entry, fwdState->server_fd);
	    break;
	case PROTO_CACHEOBJ:
	case PROTO_INTERNAL:
	    fatal_dump("Should never get here");
	    break;
	case PROTO_URN:
	    urnStart(request, entry);
	    break;
	case PROTO_WHOIS:
	    whoisStart(fwdState, fwdState->server_fd);
	    break;
	default:
	    debug(17, 1) ("fwdDispatch: Cannot retrieve '%s'\n",
		storeUrl(entry));
	    err = errorCon(ERR_UNSUP_REQ, HTTP_BAD_REQUEST);
	    err->request = requestLink(request);
	    errorAppendEntry(entry, err);
	    break;
	}
    }
}

/* PUBLIC FUNCTIONS */

void
fwdStart(int fd, StoreEntry * e, request_t * r, struct in_addr peer_addr)
{
    FwdState *fwdState;
    aclCheck_t ch;
    int answer;
    ErrorState *err;
    /*
     * peer_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */
    if (peer_addr.s_addr != no_addr.s_addr) {
	/*      
	 * Check if this host is allowed to fetch MISSES from us (miss_access)
	 */
	memset(&ch, '\0', sizeof(aclCheck_t));
	ch.src_addr = peer_addr;
	ch.request = r;
	answer = aclCheckFast(Config.accessList.miss, &ch);
	if (answer == 0) {
	    err = errorCon(ERR_FORWARDING_DENIED, HTTP_FORBIDDEN);
	    err->request = requestLink(r);
	    err->src_addr = peer_addr;
	    errorAppendEntry(e, err);
	    return;
	}
    }
    debug(17, 3) ("fwdStart: '%s'\n", storeUrl(e));
    e->mem_obj->request = requestLink(r);
    e->mem_obj->fd = fd;
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
    default:
	break;
    }
    fwdState = memAllocate(MEM_FWD_STATE);
    cbdataAdd(fwdState, MEM_FWD_STATE);
    fwdState->entry = e;
    fwdState->client_fd = fd;
    fwdState->server_fd = -1;
    fwdState->request = requestLink(r);
    fwdState->start = squid_curtime;
    storeLockObject(e);
    storeRegisterAbort(e, fwdAbort, fwdState);
    peerSelect(r, e, fwdStartComplete, fwdStartFail, fwdState);
}

/* This is called before reading data from the server side to
 * decide if the server side should abort the fetch.
 * XXX This probably breaks quick_abort!
 * When to abort?
 * - NOT if there are clients reading
 * - YES if we don't know the content length
 * - YES if we do know the content length and we don't have the
 * whole object
 */
int
fwdAbortFetch(StoreEntry * entry)
{
    MemObject *mem;
    const HttpReply *reply;
    if (storeClientWaiting(entry))
	return 0;
    mem = entry->mem_obj;
    reply = mem->reply;
    if (reply->content_length < 0)
	return 1;
    if (mem->inmem_hi < reply->content_length + reply->hdr_sz)
	return 1;
    return 0;
}

int
fwdCheckDeferRead(int fdnotused, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
#if DELAY_POOLS
    if (delayMostBytesWanted(mem, 1) == 0)
	return 1;
#endif
    if (mem->inmem_hi - storeLowestMemReaderOffset(e) < READ_AHEAD_GAP)
	return 0;
    return 1;
}

void
fwdFail(FwdState * fwdState, int err_code, http_status http_code, int xerrno)
{
#ifdef PPNR_WIP
    assert(fwdState->entry->flags.entry_fwd_hdr_wait);
#endif /* PPNR_WIP */
    debug(17, 3) ("fwdFail: %s \"%s\"\n\t%s\n",
	err_type_str[err_code],
	httpStatusString(http_code),
	storeUrl(fwdState->entry));
    fwdState->fail.err_code = err_code;
    fwdState->fail.http_code = http_code;
    fwdState->fail.xerrno = xerrno;
}

/*
 * Called when someone else calls StoreAbort() on this entry
 */
void
fwdAbort(void *data)
{
    FwdState *fwdState = data;
    debug(17, 3) ("fwdAbort: %s\n", storeUrl(fwdState->entry));
    fwdStateFree(fwdState);
}

/*
 * Frees fwdState without closing FD or generating an abort
 */
void
fwdUnregister(int fd, FwdState * fwdState)
{
    debug(17, 3) ("fwdUnregister: %s\n", storeUrl(fwdState->entry));
    assert(fd = fwdState->server_fd);
    comm_remove_close_handler(fd, fwdServerClosed, fwdState);
    fwdState->server_fd = -1;
    fwdStateFree(fwdState);
}
