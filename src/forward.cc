
/*
 * $Id: forward.cc,v 1.60 1999/05/19 19:57:43 wessels Exp $
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

static PSC fwdStartComplete;
static void fwdDispatch(FwdState *);
static void fwdConnectStart(void *);	/* should be same as EVH */
static void fwdStateFree(FwdState * fwdState);
static PF fwdConnectTimeout;
static PF fwdServerClosed;
static CNCB fwdConnectDone;
static int fwdCheckRetry(FwdState * fwdState);
static int fwdReforward(FwdState *);
static void fwdStartFail(FwdState *);
static void fwdLogReplyStatus(int tries, http_status status);
static OBJH fwdStats;
static STABH fwdAbort;

#define MAX_FWD_STATS_IDX 9
static int FwdReplyCodes[MAX_FWD_STATS_IDX + 1][HTTP_INVALID_HEADER + 1];

static void
fwdServerFree(FwdServer * fs)
{
    if (fs->peer)
	cbdataUnlock(fs->peer);
    memFree(fs, MEM_FWD_SERVER);
}

static void
fwdServersFree(FwdServer ** FS)
{
    FwdServer *fs;
    while ((fs = *FS)) {
	*FS = fs->next;
	fwdServerFree(fs);
    }
}

static void
fwdStateFree(FwdState * fwdState)
{
    StoreEntry *e = fwdState->entry;
    int sfd;
    debug(17, 3) ("fwdStateFree: %p\n", fwdState);
    assert(e->mem_obj);
    if (e->store_status == STORE_PENDING) {
	if (e->mem_obj->inmem_hi == 0) {
	    assert(fwdState->err);
	    errorAppendEntry(e, fwdState->err);
	} else {
	    EBIT_CLR(e->flags, ENTRY_FWD_HDR_WAIT);
	    storeComplete(e);
	    storeReleaseRequest(e);
	}
    }
    if (storePendingNClients(e) > 0)
	assert(!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT));
    fwdServersFree(&fwdState->servers);
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
    if (fwdState->flags.dont_retry)
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
    debug(17, 2) ("fwdServerClosed: FD %d %s\n", fd, storeUrl(fwdState->entry));
    assert(fwdState->server_fd == fd);
    fwdState->server_fd = -1;
    if (fwdCheckRetry(fwdState)) {
	debug(17, 3) ("fwdServerClosed: re-forwarding (%d tries, %d secs)\n",
	    fwdState->n_tries,
	    (int) (squid_curtime - fwdState->start));
	if (fwdState->servers->next) {
	    /* cycle */
	    FwdServer *fs = fwdState->servers;
	    FwdServer **T;
	    fwdState->servers = fs->next;
	    for (T = &fwdState->servers; *T; T = &(*T)->next);
	    *T = fs;
	    fs->next = NULL;
	}
	/* use eventAdd to break potential call sequence loops */
	eventAdd("fwdConnectStart", fwdConnectStart, fwdState, 0.0, 1);
    } else {
	fwdStateFree(fwdState);
    }
}

static void
fwdConnectDone(int server_fd, int status, void *data)
{
    FwdState *fwdState = data;
    static FwdState *current = NULL;
    FwdServer *fs = fwdState->servers;
    ErrorState *err;
    request_t *request = fwdState->request;
    assert(current != fwdState);
    current = fwdState;
    assert(fwdState->server_fd == server_fd);
    if (status == COMM_ERR_DNS) {
	fwdState->flags.dont_retry = 1;
	debug(17, 4) ("fwdConnectDone: Unknown host: %s\n",
	    request->host);
	err = errorCon(ERR_DNS_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->request = requestLink(request);
	fwdFail(fwdState, err);
	comm_close(server_fd);
    } else if (status != COMM_OK) {
	assert(fs);
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	if (fs->peer) {
	    err->host = xstrdup(fs->peer->host);
	    err->port = fs->peer->http_port;
	} else {
	    err->host = xstrdup(request->host);
	    err->port = request->port;
	}
	err->request = requestLink(request);
	fwdFail(fwdState, err);
	if (fs->peer)
	    peerCheckConnectStart(fs->peer);
	comm_close(server_fd);
    } else {
	debug(17, 3) ("fwdConnectDone: FD %d: '%s'\n", server_fd, storeUrl(fwdState->entry));
	fd_note(server_fd, storeUrl(fwdState->entry));
	fd_table[server_fd].uses++;
	fwdDispatch(fwdState);
    }
    current = NULL;
}

static void
fwdConnectTimeout(int fd, void *data)
{
    FwdState *fwdState = data;
    StoreEntry *entry = fwdState->entry;
    ErrorState *err;
    debug(17, 2) ("fwdConnectTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    assert(fd == fwdState->server_fd);
    if (entry->mem_obj->inmem_hi == 0) {
	err = errorCon(ERR_CONNECT_FAIL, HTTP_GATEWAY_TIMEOUT);
	err->request = requestLink(fwdState->request);
	err->xerrno = ETIMEDOUT;
	fwdFail(fwdState, err);
    }
    comm_close(fd);
}

static void
fwdConnectStart(void *data)
{
    FwdState *fwdState = data;
    const char *url = storeUrl(fwdState->entry);
    int fd;
    ErrorState *err;
    FwdServer *fs = fwdState->servers;
    const char *host;
    unsigned short port;
    time_t ctimeout;
    assert(fs);
    assert(fwdState->server_fd == -1);
    debug(17, 3) ("fwdConnectStart: %s\n", url);
    if (fs->peer) {
	host = fs->peer->host;
	port = fs->peer->http_port;
	ctimeout = fs->peer->connect_timeout > 0 ? fs->peer->connect_timeout
	    : Config.Timeout.peer_connect;
    } else {
	host = fwdState->request->host;
	port = fwdState->request->port;
	ctimeout = Config.Timeout.connect;
    }
    hierarchyNote(&fwdState->request->hier, fs->code, host);
    if ((fd = pconnPop(host, port)) >= 0) {
	debug(17, 3) ("fwdConnectStart: reusing pconn FD %d\n", fd);
	fwdState->server_fd = fd;
	fwdState->n_tries++;
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
	fwdFail(fwdState, err);
	fwdStateFree(fwdState);
	return;
    }
    fwdState->server_fd = fd;
    fwdState->n_tries++;
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
    FwdState *fwdState = data;
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
    err->request = requestLink(fwdState->request);
    err->xerrno = errno;
    fwdFail(fwdState, err);
    fwdStateFree(fwdState);
}

static void
fwdDispatch(FwdState * fwdState)
{
    peer *p;
    request_t *request = fwdState->request;
    StoreEntry *entry = fwdState->entry;
    debug(17, 3) ("fwdDispatch: FD %d: Fetching '%s %s'\n",
	fwdState->client_fd,
	RequestMethodStr[request->method],
	storeUrl(entry));
    /*assert(!EBIT_TEST(entry->flags, ENTRY_DISPATCHED)); */
    assert(entry->ping_status != PING_WAITING);
    assert(entry->lock_count);
    EBIT_SET(entry->flags, ENTRY_DISPATCHED);
    netdbPingSite(request->host);
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(fwdState->server_fd > -1);
    if (fwdState->servers && (p = fwdState->servers->peer)) {
	p->stats.fetches++;
	httpStart(fwdState);
    } else {
	switch (request->protocol) {
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
	    fwdFail(fwdState, errorCon(ERR_UNSUP_REQ, HTTP_BAD_REQUEST));
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
    debug(17, 3) ("fwdReforward: %s?\n", storeUrl(e));
    if (!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
	debug(17, 3) ("fwdReforward: No, ENTRY_FWD_HDR_WAIT isn't set\n");
	return 0;
    }
    if (fwdState->n_tries > 9)
	return 0;
    if (pumpMethod(fwdState->request->method))
	if (0 == pumpRestart(fwdState->request))
	    return 0;
    assert(fs);
    fwdState->servers = fs->next;
    fwdServerFree(fs);
    if (fwdState->servers == NULL) {
	debug(17, 3) ("fwdReforward: No forward-servers left\n");
	return 0;
    }
    s = e->mem_obj->reply->sline.status;
    debug(17, 3) ("fwdReforward: status %d\n", (int) s);
    return fwdReforwardableStatus(s);
}

/* PUBLIC FUNCTIONS */

void
fwdStart(int fd, StoreEntry * e, request_t * r, struct in_addr client_addr,
    struct in_addr my_addr)
{
    FwdState *fwdState;
    aclCheck_t ch;
    int answer;
    ErrorState *err;
    /*
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */
    if (client_addr.s_addr != no_addr.s_addr) {
	/*      
	 * Check if this host is allowed to fetch MISSES from us (miss_access)
	 */
	memset(&ch, '\0', sizeof(aclCheck_t));
	ch.src_addr = client_addr;
	ch.my_addr = my_addr;
	ch.request = r;
	answer = aclCheckFast(Config.accessList.miss, &ch);
	if (answer == 0) {
	    err = errorCon(ERR_FORWARDING_DENIED, HTTP_FORBIDDEN);
	    err->request = requestLink(r);
	    err->src_addr = client_addr;
	    errorAppendEntry(e, err);
	    return;
	}
    }
    debug(17, 3) ("fwdStart: '%s'\n", storeUrl(e));
    e->mem_obj->request = requestLink(r);
    e->mem_obj->fd = fd;
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
    fwdState = memAllocate(MEM_FWD_STATE);
    cbdataAdd(fwdState, memFree, MEM_FWD_STATE);
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

int
fwdCheckDeferRead(int fd, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
#if DELAY_POOLS
    if (fd < 0)
	(void) 0;
    else if (delayIsNoDelay(fd))
	(void) 0;
    else if (delayMostBytesWanted(mem, 1) == 0)
	return 1;
#endif
    if (EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT))
	return 0;
    if (mem->inmem_hi - storeLowestMemReaderOffset(e) < READ_AHEAD_GAP)
	return 0;
    return 1;
}

void
fwdFail(FwdState * fwdState, ErrorState * errorState)
{
    assert(EBIT_TEST(fwdState->entry->flags, ENTRY_FWD_HDR_WAIT));
    debug(17, 3) ("fwdFail: %s \"%s\"\n\t%s\n",
	err_type_str[errorState->type],
	httpStatusString(errorState->http_status),
	storeUrl(fwdState->entry));
    if (fwdState->err)
	errorStateFree(fwdState->err);
    fwdState->err = errorState;
}

/*
 * Called when someone else calls StoreAbort() on this entry
 */
void
fwdAbort(void *data)
{
    FwdState *fwdState = data;
    debug(17, 2) ("fwdAbort: %s\n", storeUrl(fwdState->entry));
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
	e->mem_obj->reply->sline.status);
    fwdLogReplyStatus(fwdState->n_tries, e->mem_obj->reply->sline.status);
    if (fwdReforward(fwdState)) {
	debug(17, 3) ("fwdComplete: re-forwarding %d %s\n",
	    e->mem_obj->reply->sline.status,
	    storeUrl(e));
	if (fwdState->server_fd > -1)
	    fwdUnregister(fwdState->server_fd, fwdState);
	storeEntryReset(e);
	fwdStartComplete(fwdState->servers, fwdState);
    } else {
	debug(17, 3) ("fwdComplete: not re-forwarding status %d\n",
	    e->mem_obj->reply->sline.status);
	EBIT_CLR(e->flags, ENTRY_FWD_HDR_WAIT);
	storeComplete(e);
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
    case HTTP_FORBIDDEN:
    case HTTP_INTERNAL_SERVER_ERROR:
    case HTTP_NOT_IMPLEMENTED:
    case HTTP_BAD_GATEWAY:
    case HTTP_SERVICE_UNAVAILABLE:
    case HTTP_GATEWAY_TIMEOUT:
	return 1;
    default:
	return 0;
    }
    /* NOTREACHED */
}
