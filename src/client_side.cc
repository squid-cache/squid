
/*
 * $Id: client_side.cc,v 1.391 1998/09/04 23:04:39 wessels Exp $
 *
 * DEBUG: section 33    Client-side Routines
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

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

static const char *const crlf = "\r\n";
static const char *const proxy_auth_challenge_fmt = "Basic realm=\"%s\"";

#define REQUEST_BUF_SIZE 4096
#define FAILURE_MODE_TIME 300

/* Local functions */

static CWCB clientWriteComplete;
static PF clientReadRequest;
static PF connStateFree;
static PF requestTimeout;
static int CheckQuickAbort2(const clientHttpRequest *);
static int clientCheckTransferDone(clientHttpRequest *);
static void CheckQuickAbort(clientHttpRequest *);
static void checkFailureRatio(err_type, hier_code);
static void clientProcessMiss(clientHttpRequest *);
static void clientBuildReplyHeader(clientHttpRequest * http, HttpReply * rep);
static clientHttpRequest *parseHttpRequestAbort(ConnStateData * conn, const char *uri);
static clientHttpRequest *parseHttpRequest(ConnStateData *, method_t *, int *, char **, size_t *);
static RH clientRedirectDone;
static STCB clientHandleIMSReply;
static int clientGetsOldEntry(StoreEntry * new, StoreEntry * old, request_t * request);
static int checkAccelOnly(clientHttpRequest *);
static int clientOnlyIfCached(clientHttpRequest * http);
static STCB clientSendMoreData;
static STCB clientCacheHit;
static void clientInterpretRequestHeaders(clientHttpRequest *);
static void clientProcessRequest(clientHttpRequest *);
static void clientProcessExpired(void *data);
static void clientProcessOnlyIfCachedMiss(clientHttpRequest * http);
static HttpReply *clientConstructProxyAuthReply(clientHttpRequest * http);
static int clientCachable(clientHttpRequest * http);
static int clientHierarchical(clientHttpRequest * http);
static int clientCheckContentLength(request_t * r);
static int httpAcceptDefer(void);
static log_type clientProcessRequest2(clientHttpRequest * http);

static int
checkAccelOnly(clientHttpRequest * http)
{
    /* return TRUE if someone makes a proxy request to us and
     * we are in httpd-accel only mode */
    if (!Config2.Accel.on)
	return 0;
    if (Config.onoff.accel_with_proxy)
	return 0;
    if (http->request->protocol == PROTO_CACHEOBJ)
	return 0;
    if (http->flags.accel)
	return 0;
    return 1;
}

void
clientAccessCheck(void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn = http->conn;
    const char *browser;
    if (Config.onoff.ident_lookup && conn->ident.state == IDENT_NONE) {
	identStart(-1, conn, clientAccessCheck, http);
	return;
    }
    if (checkAccelOnly(http)) {
	clientAccessCheckDone(0, http);
	return;
    }
    browser = httpHeaderGetStr(&http->request->header, HDR_USER_AGENT);
    http->acl_checklist = aclChecklistCreate(Config.accessList.http,
	http->request,
	conn->peer.sin_addr,
	browser,
	conn->ident.ident);
    aclNBCheck(http->acl_checklist, clientAccessCheckDone, http);
}

/*
 * returns true if client specified that the object must come from the cache
 * witout contacting origin server
 */
static int
clientOnlyIfCached(clientHttpRequest * http)
{
    const request_t *r = http->request;
    assert(r);
    return r->cache_control &&
	EBIT_TEST(r->cache_control->mask, CC_ONLY_IF_CACHED);
}

static HttpReply *
clientConstructProxyAuthReply(clientHttpRequest * http)
{
    ErrorState *err = errorCon(ERR_CACHE_ACCESS_DENIED, HTTP_PROXY_AUTHENTICATION_REQUIRED);
    HttpReply *rep;
    err->request = requestLink(http->request);
    rep = errorBuildReply(err);
    errorStateFree(err);
    /* add Authenticate header */
    httpHeaderPutStrf(&rep->header, HDR_PROXY_AUTHENTICATE, proxy_auth_challenge_fmt, Config.proxyAuthRealm);
    return rep;
}

StoreEntry *
clientCreateStoreEntry(clientHttpRequest * h, method_t m, request_flags flags)
{
    StoreEntry *e;
    /*
     * For erroneous requests, we might not have a h->request,
     * so make a fake one.
     */
    if (h->request == NULL)
	h->request = requestLink(requestCreate(m, PROTO_NONE, NULL));
    e = storeCreateEntry(h->uri, h->log_uri, flags, m);
    storeClientListAdd(e, h);
#if DELAY_POOLS
    delaySetStoreClient(e, h, h->request->delay_id);
#endif
    storeClientCopy(e, 0, 0, CLIENT_SOCK_SZ, memAllocate(MEM_CLIENT_SOCK_BUF), clientSendMoreData, h);
    return e;
}


void
clientAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    int page_id = -1;
    ErrorState *err = NULL;
    debug(33, 5) ("clientAccessCheckDone: '%s' answer=%d\n", http->uri, answer);
    http->acl_checklist = NULL;
    if (answer == ACCESS_ALLOWED) {
	safe_free(http->uri);
	http->uri = xstrdup(urlCanonical(http->request));
	assert(http->redirect_state == REDIRECT_NONE);
	http->redirect_state = REDIRECT_PENDING;
	redirectStart(http, clientRedirectDone, http);
    } else if (answer == ACCESS_REQ_PROXY_AUTH) {
	http->log_type = LOG_TCP_DENIED;
	http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	/* create appropriate response */
	http->entry->mem_obj->reply = clientConstructProxyAuthReply(http);
	httpReplySwapOut(http->entry->mem_obj->reply, http->entry);
	storeComplete(http->entry);
    } else {
	debug(33, 5) ("Access Denied: %s\n", http->uri);
	debug(33, 5) ("AclMatchedName = %s\n",
	    AclMatchedName ? AclMatchedName : "<null>");
	http->log_type = LOG_TCP_DENIED;
	http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName);
	/* NOTE: don't use HTTP_UNAUTHORIZED because then the
	 * stupid browser wants us to authenticate */
	err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	if (page_id > 0)
	    err->page_id = page_id;
	errorAppendEntry(http->entry, err);
    }
}

static void
clientRedirectDone(void *data, char *result)
{
    clientHttpRequest *http = data;
    request_t *new_request = NULL;
    request_t *old_request = http->request;
    debug(33, 5) ("clientRedirectDone: '%s' result=%s\n", http->uri,
	result ? result : "NULL");
    assert(http->redirect_state == REDIRECT_PENDING);
    http->redirect_state = REDIRECT_DONE;
    if (result && strcmp(result, http->uri))
	new_request = urlParse(old_request->method, result);
    if (new_request) {
	safe_free(http->uri);
	http->uri = xstrdup(urlCanonical(new_request));
	new_request->http_ver = old_request->http_ver;
	httpHeaderAppend(&new_request->header, &old_request->header);
	new_request->client_addr = old_request->client_addr;
	new_request->flags.redirected = 1;
	if (old_request->body) {
	    new_request->body = xmalloc(old_request->body_sz);
	    xmemcpy(new_request->body, old_request->body, old_request->body_sz);
	    new_request->body_sz = old_request->body_sz;
	}
	requestUnlink(old_request);
	http->request = requestLink(new_request);
    }
    clientInterpretRequestHeaders(http);
    fd_note(http->conn->fd, http->uri);
    clientProcessRequest(http);
}

static void
clientProcessExpired(void *data)
{
    clientHttpRequest *http = data;
    char *url = http->uri;
    StoreEntry *entry = NULL;
    debug(33, 3) ("clientProcessExpired: '%s'\n", http->uri);
    assert(http->entry->lastmod >= 0);
    /*
     * check if we are allowed to contact other servers
     * @?@: Instead of a 504 (Gateway Timeout) reply, we may want to return 
     *      a stale entry *if* it matches client requirements
     */
    if (clientOnlyIfCached(http)) {
	clientProcessOnlyIfCachedMiss(http);
	return;
    }
    http->request->flags.refresh = 1;
    http->old_entry = http->entry;
    entry = storeCreateEntry(url,
	http->log_uri,
	http->request->flags,
	http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    storeClientListAdd(entry, http);
    storeClientListAdd(http->old_entry, http);
#if DELAY_POOLS
    delaySetStoreClient(entry, http, http->request->delay_id);
    delaySetStoreClient(http->old_entry, http, http->request->delay_id);
#endif
    entry->lastmod = http->old_entry->lastmod;
    debug(33, 5) ("clientProcessExpired: lastmod %d\n", (int) entry->lastmod);
    entry->refcount++;		/* EXPIRED CASE */
    http->entry = entry;
    http->out.offset = 0;
    fwdStart(http->conn->fd, http->entry, http->request,
	http->conn->peer.sin_addr);
    /* Register with storage manager to receive updates when data comes in. */
    if (entry->store_status == STORE_ABORTED)
	debug(33, 0) ("clientProcessExpired: entry->swap_status == STORE_ABORTED\n");
    storeClientCopy(entry,
	http->out.offset,
	http->out.offset,
	CLIENT_SOCK_SZ,
	memAllocate(MEM_CLIENT_SOCK_BUF),
	clientHandleIMSReply,
	http);
}

static int
clientGetsOldEntry(StoreEntry * new_entry, StoreEntry * old_entry, request_t * request)
{
    const http_status status = new_entry->mem_obj->reply->sline.status;
    if (0 == status) {
	debug(33, 5) ("clientGetsOldEntry: YES, broken HTTP reply\n");
	return 1;
    }
    /* If the reply is anything but "Not Modified" then
     * we must forward it to the client */
    if (HTTP_NOT_MODIFIED != status) {
	debug(33, 5) ("clientGetsOldEntry: NO, reply=%d\n", status);
	return 0;
    }
    /* If the client did not send IMS in the request, then it
     * must get the old object, not this "Not Modified" reply */
    if (!request->flags.ims) {
	debug(33, 5) ("clientGetsOldEntry: YES, no client IMS\n");
	return 1;
    }
    /* If the client IMS time is prior to the entry LASTMOD time we
     * need to send the old object */
    if (modifiedSince(old_entry, request)) {
	debug(33, 5) ("clientGetsOldEntry: YES, modified since %d\n",
	    (int) request->ims);
	return 1;
    }
    debug(33, 5) ("clientGetsOldEntry: NO, new one is fine\n");
    return 0;
}


static void
clientHandleIMSReply(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    MemObject *mem = entry->mem_obj;
    const char *url = storeUrl(entry);
    int unlink_request = 0;
    StoreEntry *oldentry;
    int recopy = 1;
    const http_status status = mem->reply->sline.status;
    debug(33, 3) ("clientHandleIMSReply: %s, %d bytes\n", url, (int) size);
    if (size < 0 && entry->store_status != STORE_ABORTED)
	storeAbort(entry, 1);
    if (entry->store_status == STORE_ABORTED) {
	debug(33, 3) ("clientHandleIMSReply: ABORTED '%s'\n", url);
	/* We have an existing entry, but failed to validate it */
	/* Its okay to send the old one anyway */
	http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	storeUnregister(entry, http);
	storeUnlockObject(entry);
	entry = http->entry = http->old_entry;
	entry->refcount++;
    } else if (STORE_PENDING == entry->store_status && 0 == status) {
	debug(33, 3) ("clientHandleIMSReply: Incomplete headers for '%s'\n", url);
	if (size >= CLIENT_SOCK_SZ) {
	    /* will not get any bigger than that */
	    debug(33, 3) ("clientHandleIMSReply: Reply is too large '%s', using old entry\n", url);
	    /* use old entry, this repeats the code abovez */
	    http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	    storeUnregister(entry, http);
	    storeUnlockObject(entry);
	    entry = http->entry = http->old_entry;
	    entry->refcount++;
	    /* continue */
	} else {
	    storeClientCopy(entry,
		http->out.offset + size,
		http->out.offset,
		CLIENT_SOCK_SZ,
		buf,
		clientHandleIMSReply,
		http);
	    return;
	}
    } else if (clientGetsOldEntry(entry, http->old_entry, http->request)) {
	/* We initiated the IMS request, the client is not expecting
	 * 304, so put the good one back.  First, make sure the old entry
	 * headers have been loaded from disk. */
	oldentry = http->old_entry;
	http->log_type = LOG_TCP_REFRESH_HIT;
	if (oldentry->mem_obj->request == NULL) {
	    oldentry->mem_obj->request = requestLink(mem->request);
	    unlink_request = 1;
	}
	/* Don't memcpy() the whole reply structure here.  For example,
	 * www.thegist.com (Netscape/1.13) returns a content-length for
	 * 304's which seems to be the length of the 304 HEADERS!!! and
	 * not the body they refer to.  */
	httpReplyUpdateOnNotModified(oldentry->mem_obj->reply, mem->reply);
	storeTimestampsSet(oldentry);
	storeUnregister(entry, http);
	storeUnlockObject(entry);
	entry = http->entry = oldentry;
	entry->timestamp = squid_curtime;
	if (unlink_request) {
	    requestUnlink(entry->mem_obj->request);
	    entry->mem_obj->request = NULL;
	}
    } else {
	/* the client can handle this reply, whatever it is */
	http->log_type = LOG_TCP_REFRESH_MISS;
	if (HTTP_NOT_MODIFIED == mem->reply->sline.status) {
	    http->old_entry->timestamp = squid_curtime;
	    http->old_entry->refcount++;
	    http->log_type = LOG_TCP_REFRESH_HIT;
	}
	storeUnregister(http->old_entry, http);
	storeUnlockObject(http->old_entry);
	recopy = 0;
    }
    http->old_entry = NULL;	/* done with old_entry */
    assert(entry->store_status != STORE_ABORTED);
    if (recopy) {
	storeClientCopy(entry,
	    http->out.offset,
	    http->out.offset,
	    CLIENT_SOCK_SZ,
	    buf,
	    clientSendMoreData,
	    http);
    } else {
	clientSendMoreData(data, buf, size);
    }
}

int
modifiedSince(StoreEntry * entry, request_t * request)
{
    int object_length;
    MemObject *mem = entry->mem_obj;
    time_t mod_time = entry->lastmod;
    debug(33, 3) ("modifiedSince: '%s'\n", storeUrl(entry));
    if (mod_time < 0)
	mod_time = entry->timestamp;
    debug(33, 3) ("modifiedSince: mod_time = %d\n", (int) mod_time);
    if (mod_time < 0)
	return 1;
    /* Find size of the object */
    object_length = mem->reply->content_length;
    if (object_length < 0)
	object_length = contentLen(entry);
    if (mod_time > request->ims) {
	debug(33, 3) ("--> YES: entry newer than client\n");
	return 1;
    } else if (mod_time < request->ims) {
	debug(33, 3) ("-->  NO: entry older than client\n");
	return 0;
    } else if (request->imslen < 0) {
	debug(33, 3) ("-->  NO: same LMT, no client length\n");
	return 0;
    } else if (request->imslen == object_length) {
	debug(33, 3) ("-->  NO: same LMT, same length\n");
	return 0;
    } else {
	debug(33, 3) ("--> YES: same LMT, different length\n");
	return 1;
    }
}

void
clientPurgeRequest(clientHttpRequest * http)
{
    StoreEntry *entry;
    ErrorState *err = NULL;
    const cache_key *k;
    HttpReply *r;
    debug(33, 3) ("Config.onoff.enable_purge = %d\n", Config.onoff.enable_purge);
    if (!Config.onoff.enable_purge) {
	http->log_type = LOG_TCP_DENIED;
	err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	errorAppendEntry(http->entry, err);
	return;
    }
    http->log_type = LOG_TCP_MISS;
    k = storeKeyPublic(http->uri, METHOD_GET);
    if ((entry = storeGet(k)) == NULL) {
	http->http_code = HTTP_NOT_FOUND;
    } else {
	storeRelease(entry);
	http->http_code = HTTP_OK;
    }
    debug(33, 4) ("clientPurgeRequest: Not modified '%s'\n",
	storeUrl(entry));
    /*
     * Make a new entry to hold the reply to be written
     * to the client.
     */
    http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
    httpReplyReset(r = http->entry->mem_obj->reply);
    httpReplySetHeaders(r, 1.0, http->http_code, NULL, NULL, 0, 0, -1);
    httpReplySwapOut(r, http->entry);
    storeComplete(http->entry);
}

int
checkNegativeHit(StoreEntry * e)
{
    if (!EBIT_TEST(e->flag, ENTRY_NEGCACHED))
	return 0;
    if (e->expires <= squid_curtime)
	return 0;
    if (e->store_status != STORE_OK)
	return 0;
    return 1;
}

void
clientUpdateCounters(clientHttpRequest * http)
{
    int svc_time = tvSubMsec(http->start, current_time);
    ping_data *i;
    HierarchyLogEntry *H;
    Counter.client_http.requests++;
    if (isTcpHit(http->log_type))
	Counter.client_http.hits++;
    if (http->request->err_type != ERR_NONE)
	Counter.client_http.errors++;
    statHistCount(&Counter.client_http.all_svc_time, svc_time);
    /*
     * The idea here is not to be complete, but to get service times
     * for only well-defined types.  For example, we don't include
     * LOG_TCP_REFRESH_FAIL_HIT because its not really a cache hit
     * (we *tried* to validate it, but failed).
     */
    switch (http->log_type) {
    case LOG_TCP_REFRESH_HIT:
	statHistCount(&Counter.client_http.nh_svc_time, svc_time);
	break;
    case LOG_TCP_IMS_HIT:
	statHistCount(&Counter.client_http.nm_svc_time, svc_time);
	break;
    case LOG_TCP_HIT:
    case LOG_TCP_MEM_HIT:
	statHistCount(&Counter.client_http.hit_svc_time, svc_time);
	break;
    case LOG_TCP_MISS:
    case LOG_TCP_CLIENT_REFRESH_MISS:
	statHistCount(&Counter.client_http.miss_svc_time, svc_time);
	break;
    default:
	/* make compiler warnings go away */
	break;
    }
    H = &http->request->hier;
    switch (H->alg) {
    case PEER_SA_DIGEST:
	Counter.cd.times_used++;
	break;
    case PEER_SA_ICP:
	Counter.icp.times_used++;
	i = &H->ping;
	if (0 != i->stop.tv_sec && 0 != i->start.tv_sec)
	    statHistCount(&Counter.icp.query_svc_time,
		tvSubUsec(i->start, i->stop));
	if (i->timeout)
	    Counter.icp.query_timeouts++;
	break;
    case PEER_SA_NETDB:
	Counter.netdb.times_used++;
	break;
    default:
	break;
    }
}

static void
httpRequestFree(void *data)
{
    clientHttpRequest *http = data;
    clientHttpRequest **H;
    ConnStateData *conn = http->conn;
    StoreEntry *entry = http->entry;
    request_t *request = http->request;
    MemObject *mem = NULL;
    debug(33, 3) ("httpRequestFree: %s\n", storeUrl(entry));
    if (!clientCheckTransferDone(http)) {
	if (entry)
	    storeUnregister(entry, http);	/* unregister BEFORE abort */
	CheckQuickAbort(http);
	entry = http->entry;	/* reset, IMS might have changed it */
	if (entry && entry->ping_status == PING_WAITING)
	    storeReleaseRequest(entry);
    }
    assert(http->log_type < LOG_TYPE_MAX);
    if (entry)
	mem = entry->mem_obj;
    if (http->out.size || http->log_type) {
	http->al.icp.opcode = ICP_INVALID;
	http->al.url = http->log_uri;
	debug(33, 9) ("httpRequestFree: al.url='%s'\n", http->al.url);
	if (mem) {
	    http->al.http.code = mem->reply->sline.status;
	    http->al.http.content_type = strBuf(mem->reply->content_type);
	}
	http->al.cache.caddr = conn->log_addr;
	http->al.cache.size = http->out.size;
	http->al.cache.code = http->log_type;
	http->al.cache.msec = tvSubMsec(http->start, current_time);
	if (request->user_ident[0])
	    http->al.cache.ident = request->user_ident;
	else
	    http->al.cache.ident = conn->ident.ident;
	if (request) {
	    Packer p;
	    MemBuf mb;
	    memBufDefInit(&mb);
	    packerToMemInit(&p, &mb);
	    httpHeaderPackInto(&request->header, &p);
	    http->al.http.method = request->method;
	    http->al.headers.request = xstrdup(mb.buf);
	    http->al.hier = request->hier;
	    packerClean(&p);
	    memBufClean(&mb);
	}
	accessLogLog(&http->al);
	clientUpdateCounters(http);
	clientdbUpdate(conn->peer.sin_addr, http->log_type, PROTO_HTTP, http->out.size);
    }
    if (http->redirect_state == REDIRECT_PENDING)
	redirectUnregister(http->uri, http);
    if (http->acl_checklist)
	aclChecklistFree(http->acl_checklist);
    if (request)
	checkFailureRatio(request->err_type, http->al.hier.code);
    safe_free(http->uri);
    safe_free(http->log_uri);
    safe_free(http->al.headers.request);
    safe_free(http->al.headers.reply);
    stringClean(&http->range_iter.boundary);
    if (entry) {
	http->entry = NULL;
	storeUnregister(entry, http);
	storeUnlockObject(entry);
    }
    /* old_entry might still be set if we didn't yet get the reply
     * code in clientHandleIMSReply() */
    if (http->old_entry) {
	storeUnregister(http->old_entry, http);
	storeUnlockObject(http->old_entry);
	http->old_entry = NULL;
    }
    requestUnlink(http->request);
    assert(http != http->next);
    assert(http->conn->chr != NULL);
    H = &http->conn->chr;
    while (*H) {
	if (*H == http)
	    break;
	H = &(*H)->next;
    }
    assert(*H != NULL);
    *H = http->next;
    http->next = NULL;
    cbdataFree(http);
}

/* This is a handler normally called by comm_close() */
static void
connStateFree(int fd, void *data)
{
    ConnStateData *connState = data;
    clientHttpRequest *http;
    debug(33, 3) ("connStateFree: FD %d\n", fd);
    assert(connState != NULL);
    while ((http = connState->chr) != NULL) {
	assert(http->conn == connState);
	assert(connState->chr != connState->chr->next);
	httpRequestFree(http);
    }
    if (connState->ident.fd > -1)
	comm_close(connState->ident.fd);
    safe_free(connState->in.buf);
    /* XXX account connState->in.buf */
    pconnHistCount(0, connState->nrequests);
    cbdataFree(connState);
}

static void
clientInterpretRequestHeaders(clientHttpRequest * http)
{
    request_t *request = http->request;
    const HttpHeader *req_hdr = &request->header;
#if USE_USERAGENT_LOG
    const char *str;
#endif
    request->imslen = -1;
    request->ims = httpHeaderGetTime(req_hdr, HDR_IF_MODIFIED_SINCE);
    if (request->ims > 0)
	request->flags.ims = 1;
    if (httpHeaderHas(req_hdr, HDR_PRAGMA)) {
	String s = httpHeaderGetList(req_hdr, HDR_PRAGMA);
	if (strListIsMember(&s, "no-cache", ',')) {
#if HTTP_VIOLATIONS
	    if (Config.onoff.reload_into_ims)
		request->flags.nocache_hack = 1;
	    else if (refresh_nocache_hack)
		request->flags.nocache_hack = 1;
	    else
#endif
		request->flags.nocache = 1;
	}
	stringClean(&s);
    }
    /* ignore range header in non-GETs */
    if (request->method == METHOD_GET) {
	request->range = httpHeaderGetRange(req_hdr);
	if (request->range)
	    request->flags.range = 1;
    }
    if (httpHeaderHas(req_hdr, HDR_AUTHORIZATION))
	request->flags.auth = 1;
    if (request->login[0] != '\0')
	request->flags.auth = 1;
    if (httpMsgIsPersistent(request->http_ver, req_hdr))
	request->flags.proxy_keepalive = 1;
    if (httpHeaderHas(req_hdr, HDR_VIA)) {
	String s = httpHeaderGetList(req_hdr, HDR_VIA);
	/* ThisCache cannot be a member of Via header, "1.0 ThisCache" can */
	if (strListIsSubstr(&s, ThisCache, ',')) {
	    debug(33, 1) ("WARNING: Forwarding loop detected for '%s'\n",
		http->uri);
	    debug(33, 1) ("--> %s\n", strBuf(s));
	    request->flags.loopdetect = 1;
	}
#if FORW_VIA_DB
	fvdbCountVia(strBuf(s));
#endif
	stringClean(&s);
    }
#if USE_USERAGENT_LOG
    if ((str = httpHeaderGetStr(req_hdr, HDR_USER_AGENT)))
	logUserAgent(fqdnFromAddr(http->conn->peer.sin_addr), str);
#endif
#if FORW_VIA_DB
    if (httpHeaderHas(req_hdr, HDR_X_FORWARDED_FOR)) {
	String s = httpHeaderGetList(req_hdr, HDR_X_FORWARDED_FOR);
	fvdbCountForw(strBuf(s));
	stringClean(&s);
    }
#endif
    request->cache_control = httpHeaderGetCc(req_hdr);
    if (request->method == METHOD_TRACE) {
	request->max_forwards = httpHeaderGetInt(req_hdr, HDR_MAX_FORWARDS);
    }
    if (clientCachable(http))
	request->flags.cachable = 1;
    if (clientHierarchical(http))
	request->flags.hierarchical = 1;
#if DELAY_POOLS
    if (delayClient(http)) {
	debug(33, 5) ("clientInterpretRequestHeaders: delay request class %d position %d\n",
	    request->delay_id >> 16,
	    request->delay_id & 0xFFFF);
    }
#endif
    debug(33, 5) ("clientInterpretRequestHeaders: REQ_NOCACHE = %s\n",
	request->flags.nocache ? "SET" : "NOT SET");
    debug(33, 5) ("clientInterpretRequestHeaders: REQ_CACHABLE = %s\n",
	request->flags.cachable ? "SET" : "NOT SET");
    debug(33, 5) ("clientInterpretRequestHeaders: REQ_HIERARCHICAL = %s\n",
	request->flags.hierarchical ? "SET" : "NOT SET");
}

static int
clientCheckContentLength(request_t * r)
{
    /* We only require a content-length for "upload" methods */
    if (!pumpMethod(r->method))
	return 1;
    if (httpHeaderGetInt(&r->header, HDR_CONTENT_LENGTH) < 0)
	return 0;
    return 1;
}

static int
clientCachable(clientHttpRequest * http)
{
    const char *url = http->uri;
    request_t *req = http->request;
    method_t method = req->method;
    aclCheck_t ch;
    memset(&ch, '\0', sizeof(ch));
    /*
     * Hopefully, nobody really wants 'no_cache' by client's IP
     * address, but if they do, this should work if they use IP
     * addresses in their ACLs, or if the client's address is in
     * the FQDN cache.
     *
     * This may not work yet for 'dst' and 'dst_domain' ACLs.
     */
    ch.src_addr = http->conn->peer.sin_addr;
    ch.request = http->request;
    /*
     * aclCheckFast returns 1 for ALLOW and 0 for DENY.  The default
     * is ALLOW, so we require 'no_cache DENY foo' in squid.conf
     * to indicate uncachable objects.
     */
    if (!aclCheckFast(Config.accessList.noCache, &ch))
	return 0;
    if (req->protocol == PROTO_HTTP)
	return httpCachable(method);
    /* FTP is always cachable */
    if (req->protocol == PROTO_GOPHER)
	return gopherCachable(url);
    if (req->protocol == PROTO_WAIS)
	return 0;
    if (method == METHOD_CONNECT)
	return 0;
    if (method == METHOD_TRACE)
	return 0;
    if (req->protocol == PROTO_CACHEOBJ)
	return 0;
    return 1;
}

/* Return true if we can query our neighbors for this object */
static int
clientHierarchical(clientHttpRequest * http)
{
    const char *url = http->uri;
    request_t *request = http->request;
    method_t method = request->method;
    const wordlist *p = NULL;

    /* IMS needs a private key, so we can use the hierarchy for IMS only
     * if our neighbors support private keys */
    if (request->flags.ims && !neighbors_do_private_keys)
	return 0;
    if (request->flags.auth)
	return 0;
    if (method == METHOD_TRACE)
	return 1;
    if (method != METHOD_GET)
	return 0;
    /* scan hierarchy_stoplist */
    for (p = Config.hierarchy_stoplist; p; p = p->next)
	if (strstr(url, p->key))
	    return 0;
    if (request->flags.loopdetect)
	return 0;
    if (request->protocol == PROTO_HTTP)
	return httpCachable(method);
    if (request->protocol == PROTO_GOPHER)
	return gopherCachable(url);
    if (request->protocol == PROTO_WAIS)
	return 0;
    if (request->protocol == PROTO_CACHEOBJ)
	return 0;
    return 1;
}

int
isTcpHit(log_type code)
{
    /* this should be a bitmap for better optimization */
    if (code == LOG_TCP_HIT)
	return 1;
    if (code == LOG_TCP_IMS_HIT)
	return 1;
    if (code == LOG_TCP_REFRESH_FAIL_HIT)
	return 1;
    if (code == LOG_TCP_REFRESH_HIT)
	return 1;
    if (code == LOG_TCP_NEGATIVE_HIT)
	return 1;
    if (code == LOG_TCP_MEM_HIT)
	return 1;
    return 0;
}

/*
 * returns true if If-Range specs match reply, false otherwise
 */
static int
clientIfRangeMatch(clientHttpRequest * http, HttpReply * rep)
{
    const TimeOrTag spec = httpHeaderGetTimeOrTag(&http->request->header, HDR_IF_RANGE);
    /* check for parsing falure */
    if (!spec.valid)
	return 0;
    /* got an ETag? */
    if (spec.tag.str) {
	ETag rep_tag = httpHeaderGetETag(&rep->header, HDR_ETAG);
	debug(33, 3) ("clientIfRangeMatch: ETags: %s and %s\n",
	    spec.tag.str, rep_tag.str ? rep_tag.str : "<none>");
	if (!rep_tag.str)
	    return 0;		/* entity has no etag to compare with! */
	if (spec.tag.weak || rep_tag.weak) {
	    debug(33, 1) ("clientIfRangeMatch: Weak ETags are not allowed in If-Range: %s ? %s\n",
		spec.tag.str, rep_tag.str);
	    return 0;		/* must use strong validator for sub-range requests */
	}
	return etagIsEqual(&rep_tag, &spec.tag);
    }
    /* got modification time? */
    if (spec.time >= 0) {
	return http->entry->lastmod <= spec.time;
    }
    assert(0);			/* should not happen */
    return 0;
}

/* adds appropriate Range headers if needed */
static void
clientBuildRangeHeader(clientHttpRequest * http, HttpReply * rep)
{
    HttpHeader *hdr = rep ? &rep->header : 0;
    const char *range_err = NULL;
    assert(http->request->range);
    /* check if we still want to do ranges */
    if (!rep)
	range_err = "no [parse-able] reply";
    else if (rep->sline.status != HTTP_OK)
	range_err = "wrong status code";
    else if (httpHeaderHas(hdr, HDR_CONTENT_RANGE))
	range_err = "origin server does ranges";
    else if (rep->content_length < 0)
	range_err = "unknown length";
    else if (rep->content_length != http->entry->mem_obj->reply->content_length)
	range_err = "INCONSISTENT length";	/* a bug? */
    else if (httpHeaderHas(&http->request->header, HDR_IF_RANGE) && !clientIfRangeMatch(http, rep))
	range_err = "If-Range match failed";
    else if (!httpHdrRangeCanonize(http->request->range, rep->content_length))
	range_err = "canonization failed";
    else if (httpHdrRangeIsComplex(http->request->range))
	range_err = "too complex range header";
    /* get rid of our range specs on error */
    if (range_err) {
	debug(33, 2) ("clientBuildRangeHeader: will not do ranges: %s.\n", range_err);
	httpHdrRangeDestroy(http->request->range);
	http->request->range = NULL;
    } else {
	const int spec_count = http->request->range->specs.count;
	debug(33, 2) ("clientBuildRangeHeader: range spec count: %d clen: %d\n",
	    spec_count, rep->content_length);
	assert(spec_count > 0);
	/* ETags should not be returned with Partial Content replies? */
	httpHeaderDelById(hdr, HDR_ETAG);
	/* append appropriate header(s) */
	if (spec_count == 1) {
	    HttpHdrRangePos pos = HttpHdrRangeInitPos;
	    const HttpHdrRangeSpec *spec = httpHdrRangeGetSpec(http->request->range, &pos);
	    assert(spec);
	    /* append Content-Range */
	    httpHeaderAddContRange(hdr, *spec, rep->content_length);
	    /* set new Content-Length to the actual number of OCTETs
	     * transmitted in the message-body */
	    httpHeaderDelById(hdr, HDR_CONTENT_LENGTH);
	    httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, spec->length);
	    debug(33, 2) ("clientBuildRangeHeader: actual content length: %d\n", spec->length);
	} else {
	    /* multipart! */
	    /* generate boundary string */
	    http->range_iter.boundary = httpHdrRangeBoundaryStr(http);
	    /* delete old Content-Type, add ours */
	    httpHeaderDelById(hdr, HDR_CONTENT_TYPE);
	    httpHeaderPutStrf(hdr, HDR_CONTENT_TYPE,
		"multipart/byteranges; boundary=\"%s\"",
		strBuf(http->range_iter.boundary));
	    /* no need for Content-Length in multipart responses */
	    /* but we must delete the original one if we cannot (yet)
	     * calculate the actual length */
	    httpHeaderDelById(hdr, HDR_CONTENT_LENGTH);
	}
    }
}

/* filters out unwanted entries from original reply header
 * adds extra entries if we have more info than origin server
 * adds Squid specific entries */
static void
clientBuildReplyHeader(clientHttpRequest * http, HttpReply * rep)
{
    HttpHeader *hdr = &rep->header;
    int is_hit = isTcpHit(http->log_type);
    request_t *request = http->request;
#if DONT_FILTER_THESE
    /* but you might want to if you run Squid as an HTTP accelerator */
    /* httpHeaderDelById(hdr, HDR_ACCEPT_RANGES); */
    httpHeaderDelById(hdr, HDR_ETAG);
#endif
    httpHeaderDelById(hdr, HDR_PROXY_CONNECTION);
    /* here: Keep-Alive is a field-name, not a connection directive! */
    httpHeaderDelByName(hdr, "Keep-Alive");
    /* remove Set-Cookie if a hit */
    if (is_hit)
	httpHeaderDelById(hdr, HDR_SET_COOKIE);
    /* handle Connection header */
    if (httpHeaderHas(hdr, HDR_CONNECTION)) {
	/* anything that matches Connection list member will be deleted */
	String strConnection = httpHeaderGetList(hdr, HDR_CONNECTION);
	const HttpHeaderEntry *e;
	HttpHeaderPos pos = HttpHeaderInitPos;
	/*
	 * think: on-average-best nesting of the two loops (hdrEntry
	 * and strListItem) @?@
	 */
	/*
	 * maybe we should delete standard stuff ("keep-alive","close")
	 * from strConnection first?
	 */
	while ((e = httpHeaderGetEntry(hdr, &pos))) {
	    if (strListIsMember(&strConnection, strBuf(e->name), ','))
		httpHeaderDelAt(hdr, pos);
	}
	httpHeaderDelById(hdr, HDR_CONNECTION);
	stringClean(&strConnection);
    }
    /* Handle Ranges */
    if (request->range)
	clientBuildRangeHeader(http, rep);
    /*
     * Add Age header, not that our header must replace Age headers
     * from other caches if any
     */
    if (http->entry->timestamp > 0) {
	httpHeaderDelById(hdr, HDR_AGE);
	/*
	 * we do not follow HTTP/1.1 precisely here becuase we rely
	 * on Date header when computing entry->timestamp; we should
	 * be using _request_ time if Date header is not available
	 * or if it is out of sync
	 */
	httpHeaderPutInt(hdr, HDR_AGE,
	    http->entry->timestamp <= squid_curtime ?
	    squid_curtime - http->entry->timestamp : 0);
    }
    /* Append X-Cache */
    httpHeaderPutStrf(hdr, HDR_X_CACHE, "%s from %s",
	is_hit ? "HIT" : "MISS", getMyHostname());
#if USE_CACHE_DIGESTS
    /* Append X-Cache-Lookup: -- temporary hack, to be removed @?@ @?@ */
    httpHeaderPutStrf(hdr, HDR_X_CACHE_LOOKUP, "%s from %s:%d",
	http->lookup_type ? http->lookup_type : "NONE",
	getMyHostname(), Config.Port.http->i);
#endif
    /* Only replies with valid Content-Length can be sent with keep-alive */
    if (request->method != METHOD_HEAD &&
	http->entry->mem_obj->reply->content_length < 0)
	request->flags.proxy_keepalive = 0;
    /* Signal keep-alive if needed */
    httpHeaderPutStr(hdr,
	http->flags.accel ? HDR_CONNECTION : HDR_PROXY_CONNECTION,
	request->flags.proxy_keepalive ? "keep-alive" : "close");
    /* Accept-Range header for cached objects if not there already */
    if (is_hit && !httpHeaderHas(hdr, HDR_ACCEPT_RANGES))
	httpHeaderPutStr(hdr, HDR_ACCEPT_RANGES, "bytes");
#if ADD_X_REQUEST_URI
    /*
     * Knowing the URI of the request is useful when debugging persistent
     * connections in a client; we cannot guarantee the order of http headers,
     * but X-Request-URI is likely to be the very last header to ease use from a
     * debugger [hdr->entries.count-1].
     */
    httpHeaderPutStr(hdr, HDR_X_REQUEST_URI,
	http->entry->mem_obj->url ? http->entry->mem_obj->url : http->uri);
#endif
}

static HttpReply *
clientBuildReply(clientHttpRequest * http, const char *buf, size_t size)
{
    HttpReply *rep = httpReplyCreate();
#if DOUBTFUL
    assert(size <= 4096);	/* httpReplyParse depends on this */
#endif
    if (httpReplyParse(rep, buf)) {
	/* enforce 1.0 reply version */
	rep->sline.version = 1.0;
	/* do header conversions */
	clientBuildReplyHeader(http, rep);
	/* if we do ranges, change status to "Partial Content" */
	if (http->request->range)
	    httpStatusLineSet(&rep->sline, rep->sline.version, HTTP_PARTIAL_CONTENT, NULL);
    } else {
	/* parsing failure, get rid of the invalid reply */
	httpReplyDestroy(rep);
	rep = NULL;
	/* if we were going to do ranges, backoff */
	if (http->request->range)
	    clientBuildRangeHeader(http, rep);	/* will fail and destroy request->range */
    }
    return rep;
}

/*
 * clientCacheHit should only be called until the HTTP reply headers
 * have been parsed.  Normally this should be a single call, but
 * it might take more than one.  As soon as we have the headers,
 * we hand off to clientSendMoreData, clientProcessExpired, or
 * clientProcessMiss.
 */
static void
clientCacheHit(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    StoreEntry *e = http->entry;
    MemObject *mem;
    request_t *r = http->request;
    debug(33, 3) ("clientCacheHit: %s, %d bytes\n", http->uri, (int) size);
    if (http->entry == NULL) {
	memFree(MEM_CLIENT_SOCK_BUF, buf);
	debug(33, 3) ("clientCacheHit: request aborted\n");
	return;
    } else if (size < 0) {
	/* swap in failure */
	memFree(MEM_CLIENT_SOCK_BUF, buf);
	debug(33, 3) ("clientCacheHit: swapin failure for %s\n", http->uri);
	http->log_type = LOG_TCP_SWAPFAIL_MISS;
	if ((e = http->entry)) {
	    http->entry = NULL;
	    storeUnregister(e, http);
	    storeUnlockObject(e);
	}
	clientProcessMiss(http);
	return;
    }
    assert(size > 0);
    mem = e->mem_obj;
    assert(e->store_status != STORE_ABORTED);
    if (mem->reply->sline.status == 0) {
	/*
	 * we don't have full reply headers yet; either wait for more or
	 * punt to clientProcessMiss.
	 */
	if (e->mem_status == IN_MEMORY || e->store_status == STORE_OK) {
	    memFree(MEM_CLIENT_SOCK_BUF, buf);
	    clientProcessMiss(http);
	} else if (size == CLIENT_SOCK_SZ && http->out.offset == 0) {
	    memFree(MEM_CLIENT_SOCK_BUF, buf);
	    clientProcessMiss(http);
	} else {
	    debug(33, 3) ("clientCacheHit: waiting for HTTP reply headers\n");
	    storeClientCopy(e,
		http->out.offset + size,
		http->out.offset,
		CLIENT_SOCK_SZ,
		buf,
		clientCacheHit,
		http);
	}
	return;
    }
    /*
     * Got the headers, now grok them
     */
    assert(http->log_type == LOG_TCP_HIT);
    if (checkNegativeHit(e)) {
	http->log_type = LOG_TCP_NEGATIVE_HIT;
	clientSendMoreData(data, buf, size);
    } else if (refreshCheck(e, r, 0) && !http->flags.internal) {
	/*
	 * We hold a stale copy; it needs to be validated
	 */
	if (e->lastmod < 0) {
	    /*
	     * Previous reply didn't have a Last-Modified header,
	     * we cannot revalidate it.
	     */
	    http->log_type = LOG_TCP_MISS;
	    clientProcessMiss(http);
	} else if (r->flags.nocache) {
	    /*
	     * This did not match a refresh pattern that overrides no-cache
	     * we should honour the client no-cache header.
	     */
	    http->log_type = LOG_TCP_CLIENT_REFRESH_MISS;
	    clientProcessMiss(http);
	} else if (r->protocol == PROTO_HTTP) {
	    /*
	     * Object needs to be revalidated
	     * XXX This could apply to FTP as well, if Last-Modified is known.
	     */
	    http->log_type = LOG_TCP_REFRESH_MISS;
	    clientProcessExpired(http);
	} else {
	    /*
	     * We don't know how to re-validate other protocols. Handle
	     * them as if the object has expired.
	     */
	    http->log_type = LOG_TCP_MISS;
	    clientProcessMiss(http);
	}
	memFree(MEM_CLIENT_SOCK_BUF, buf);
    } else if (r->flags.ims) {
	/*
	 * Handle If-Modified-Since requests from the client
	 */
	if (mem->reply->sline.status != HTTP_OK) {
	    debug(33, 4) ("clientCacheHit: Reply code %d != 200\n",
		mem->reply->sline.status);
	    memFree(MEM_CLIENT_SOCK_BUF, buf);
	    clientProcessMiss(http);
	} else if (modifiedSince(e, http->request)) {
	    http->log_type = LOG_TCP_IMS_HIT;
	    clientSendMoreData(data, buf, size);
	} else {
	    MemBuf mb = httpPacked304Reply(e->mem_obj->reply);
	    http->log_type = LOG_TCP_IMS_HIT;
	    memFree(MEM_CLIENT_SOCK_BUF, buf);
	    storeUnregister(e, http);
	    storeUnlockObject(e);
	    e = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	    http->entry = e;
	    httpReplyParse(e->mem_obj->reply, mb.buf);
	    storeAppend(e, mb.buf, mb.size);
	    memBufClean(&mb);
	    storeComplete(e);
	}
    } else {
	/*
	 * plain ol' cache hit
	 */
	if (e->mem_status == IN_MEMORY)
	    http->log_type = LOG_TCP_MEM_HIT;
	clientSendMoreData(data, buf, size);
    }
}


/* extracts a "range" from *buf and appends them to mb, updating all offsets and such */
static void
clientPackRange(clientHttpRequest * http, HttpHdrRangeIter * i, const char **buf, ssize_t * size, MemBuf * mb)
{
    const size_t copy_sz = i->debt_size <= *size ? i->debt_size : *size;
    off_t body_off = http->out.offset - i->prefix_size;
    assert(*size > 0);
    assert(i->spec);
    /* intersection of "have" and "need" ranges must not be empty */
    assert(body_off < i->spec->offset + i->spec->length);
    assert(body_off + *size > i->spec->offset);
    /* put boundary and headers at the beginning of range in a multi-range */
    if (http->request->range->specs.count > 1 && i->debt_size == i->spec->length) {
	HttpReply *rep = http->entry->mem_obj ?		/* original reply */
	http->entry->mem_obj->reply : NULL;
	HttpHeader hdr;
	Packer p;
	assert(rep);
	/* put boundary */
	debug(33, 5) ("clientPackRange: appending boundary: %s\n", strBuf(i->boundary));
	/* rfc2046 requires to _prepend_ boundary with <crlf>! */
	memBufPrintf(mb, "\r\n--%s\r\n", strBuf(i->boundary));
	httpHeaderInit(&hdr, hoReply);
	if (httpHeaderHas(&rep->header, HDR_CONTENT_TYPE))
	    httpHeaderPutStr(&hdr, HDR_CONTENT_TYPE, httpHeaderGetStr(&rep->header, HDR_CONTENT_TYPE));
	httpHeaderAddContRange(&hdr, *i->spec, rep->content_length);
	packerToMemInit(&p, mb);
	httpHeaderPackInto(&hdr, &p);
	packerClean(&p);
	httpHeaderClean(&hdr);
	/* append <crlf> (we packed a header, not a reply */
	memBufPrintf(mb, "\r\n");
    }
    /* append */
    debug(33, 3) ("clientPackRange: appending %d bytes\n", copy_sz);
    memBufAppend(mb, *buf, copy_sz);
    /* update offsets */
    *size -= copy_sz;
    i->debt_size -= copy_sz;
    body_off += copy_sz;
    *buf += copy_sz;
    http->out.offset = body_off + i->prefix_size;	/* sync */
    /* paranoid check */
    assert(*size >= 0 && i->debt_size >= 0);
}

/* returns true if there is still data available to pack more ranges
 * increments iterator "i"
 * used by clientPackMoreRanges */
static int
clientCanPackMoreRanges(const clientHttpRequest * http, HttpHdrRangeIter * i, ssize_t size)
{
    /* first update "i" if needed */
    if (!i->debt_size) {
	if ((i->spec = httpHdrRangeGetSpec(http->request->range, &i->pos)))
	    i->debt_size = i->spec->length;
    }
    assert(!i->debt_size == !i->spec);	/* paranoid sync condition */
    /* continue condition: need_more_data && have_more_data */
    return i->spec && size > 0;
}

/* extracts "ranges" from buf and appends them to mb, updating all offsets and such */
/* returns true if we need more data */
static int
clientPackMoreRanges(clientHttpRequest * http, const char *buf, ssize_t size, MemBuf * mb)
{
    HttpHdrRangeIter *i = &http->range_iter;
    /* offset in range specs does not count the prefix of an http msg */
    off_t body_off = http->out.offset - i->prefix_size;
    assert(size >= 0);
    /* check: reply was parsed and range iterator was initialized */
    assert(i->prefix_size > 0);
    /* filter out data according to range specs */
    /* note: order of loop conditions is significant! */
    while (clientCanPackMoreRanges(http, i, size)) {
	off_t start;		/* offset of still missing data */
	assert(i->spec);
	start = i->spec->offset + i->spec->length - i->debt_size;
	debug(33, 2) ("clientPackMoreRanges: in:  offset: %d size: %d\n",
	    (int) body_off, size);
	debug(33, 2) ("clientPackMoreRanges: out: start: %d spec[%d]: [%d, %d), len: %d debt: %d\n",
	    (int) start, (int) i->pos, i->spec->offset, (int) (i->spec->offset + i->spec->length), i->spec->length, i->debt_size);
	assert(body_off <= start);	/* we did not miss it */
	/* skip up to start */
	if (body_off + size > start) {
	    const size_t skip_size = start - body_off;
	    body_off = start;
	    size -= skip_size;
	    buf += skip_size;
	} else {
	    /* has not reached start yet */
	    body_off += size;
	    size = 0;
	    buf = NULL;
	}
	/* put next chunk if any */
	if (size) {
	    http->out.offset = body_off + i->prefix_size;	/* sync */
	    clientPackRange(http, i, &buf, &size, mb);
	    body_off = http->out.offset - i->prefix_size;	/* sync */
	}
    }
    assert(!i->debt_size == !i->spec);	/* paranoid sync condition */
    debug(33, 2) ("clientPackMoreRanges: buf exhausted: in:  offset: %d size: %d need_more: %d\n",
	(int) body_off, size, i->debt_size);
    if (i->debt_size) {
	debug(33, 2) ("clientPackMoreRanges: need more: spec[%d]: [%d, %d), len: %d\n",
	    (int) i->pos, i->spec->offset, (int) (i->spec->offset + i->spec->length), i->spec->length);
	/* skip the data we do not need if possible */
	if (i->debt_size == i->spec->length)	/* at the start of the cur. spec */
	    body_off = i->spec->offset;
	else
	    assert(body_off == i->spec->offset + i->spec->length - i->debt_size);
    } else if (http->request->range->specs.count > 1) {
	/* put terminating boundary for multiparts */
	memBufPrintf(mb, "\r\n--%s--\r\n", strBuf(i->boundary));
    }
    http->out.offset = body_off + i->prefix_size;	/* sync */
    return i->debt_size > 0;
}

/*
 * accepts chunk of a http message in buf, parses prefix, filters headers and
 * such, writes processed message to the client's socket
 */
static void
clientSendMoreData(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    ConnStateData *conn = http->conn;
    int fd = conn->fd;
    HttpReply *rep = NULL;
    const char *body_buf = buf;
    ssize_t body_size = size;
    MemBuf mb;
    ssize_t check_size = 0;
    debug(33, 5) ("clientSendMoreData: %s, %d bytes\n", http->uri, (int) size);
    assert(size <= CLIENT_SOCK_SZ);
    assert(http->request != NULL);
    debug(33, 5) ("clientSendMoreData: FD %d '%s', out.offset=%d \n",
	fd, storeUrl(entry), (int) http->out.offset);
    if (conn->chr != http) {
	/* there is another object in progress, defer this one */
	debug(33, 1) ("clientSendMoreData: Deferring %s\n", storeUrl(entry));
	memFree(MEM_CLIENT_SOCK_BUF, buf);
	return;
    } else if (entry && entry->store_status == STORE_ABORTED) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	memFree(MEM_CLIENT_SOCK_BUF, buf);
	return;
    } else if (size < 0) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	memFree(MEM_CLIENT_SOCK_BUF, buf);
	return;
    } else if (size == 0) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	memFree(MEM_CLIENT_SOCK_BUF, buf);
	return;
    }
    if (http->out.offset == 0) {
	if (Config.onoff.log_mime_hdrs) {
	    size_t k;
	    if ((k = headersEnd(buf, size))) {
		safe_free(http->al.headers.reply);
		http->al.headers.reply = xcalloc(k + 1, 1);
		xstrncpy(http->al.headers.reply, buf, k);
	    }
	}
	rep = clientBuildReply(http, buf, size);
	if (rep) {
	    body_size = size - rep->hdr_sz;
	    assert(body_size >= 0);
	    body_buf = buf + rep->hdr_sz;
	    http->range_iter.prefix_size = rep->hdr_sz;
	    debug(33, 3) ("clientSendMoreData: Appending %d bytes after %d bytes of headers\n",
		body_size, rep->hdr_sz);
	} else if (size < CLIENT_SOCK_SZ && entry->store_status == STORE_PENDING) {
	    /* wait for more to arrive */
	    storeClientCopy(entry,
		http->out.offset + size,
		http->out.offset,
		CLIENT_SOCK_SZ,
		buf,
		clientSendMoreData,
		http);
	    return;
	}
	/* reset range iterator */
	http->range_iter.pos = HttpHdrRangeInitPos;
    }
    if (http->request->method == METHOD_HEAD) {
	if (rep) {
	    /* do not forward body for HEAD replies */
	    body_size = 0;
	    http->flags.done_copying = 1;
	} else {
	    /*
	     * If we are here, then store_status == STORE_OK and it
	     * seems we have a HEAD repsponse which is missing the
	     * empty end-of-headers line (home.mira.net, phttpd/0.99.72
	     * does this).  Because clientBuildReply() fails we just
	     * call this reply a body, set the done_copying flag and
	     * continue...
	     */
	    http->flags.done_copying = 1;
	}
    }
    /* write headers and/or body if any */
    assert(rep || (body_buf && body_size));
    /* init mb; put status line and headers if any */
    if (rep) {
	mb = httpReplyPack(rep);
	http->out.offset += rep->hdr_sz;
	check_size += rep->hdr_sz;
	httpReplyDestroy(rep);
	rep = NULL;
    } else {
	/* leave space for growth incase we do ranges */
	memBufInit(&mb, CLIENT_SOCK_SZ, 2 * CLIENT_SOCK_SZ);
    }
    /* append body if any */
    if (body_buf && body_size) {
	if (http->request->range) {
	    /* Only GET requests should have ranges */
	    assert(http->request->method == METHOD_GET);
	    /* clientPackMoreRanges() updates http->out.offset */
	    /* force the end of the transfer if we are done */
	    if (!clientPackMoreRanges(http, body_buf, body_size, &mb))
		http->flags.done_copying = 1;
	} else {
	    http->out.offset += body_size;
	    check_size += body_size;
	    memBufAppend(&mb, body_buf, body_size);
	}
    }
    if (!http->request->range && http->request->method == METHOD_GET)
	assert(check_size == size);
    /* write */
    comm_write_mbuf(fd, mb, clientWriteComplete, http);
    /* if we don't do it, who will? */
    memFree(MEM_CLIENT_SOCK_BUF, buf);
}

static
void
clientKeepaliveNextRequest(clientHttpRequest * http)
{
    ConnStateData *conn = http->conn;
    StoreEntry *entry;
    debug(33, 3) ("clientKeepaliveNextRequest: FD %d\n", conn->fd);
    conn->defer.until = 0;	/* Kick it to read a new request */
    httpRequestFree(http);
    if ((http = conn->chr) != NULL) {
	debug(33, 1) ("clientKeepaliveNextRequest: FD %d Sending next\n",
	    conn->fd);
	entry = http->entry;
	if (0 == storeClientCopyPending(entry, http)) {
	    if (entry->store_status == STORE_ABORTED)
		debug(33, 0) ("clientKeepaliveNextRequest: entry->swap_status == STORE_ABORTED\n");
	    storeClientCopy(entry,
		http->out.offset,
		http->out.offset,
		CLIENT_SOCK_SZ,
		memAllocate(MEM_CLIENT_SOCK_BUF),
		clientSendMoreData,
		http);
	}
    } else {
	debug(33, 5) ("clientKeepaliveNextRequest: FD %d reading next request\n",
	    conn->fd);
	fd_note(conn->fd, "Reading next request");
	/*
	 * Set the timeout BEFORE calling clientReadRequest().
	 */
	commSetTimeout(conn->fd, 15, requestTimeout, conn);
	clientReadRequest(conn->fd, conn);	/* Read next request */
	/*
	 * Note, the FD may be closed at this point.
	 */
    }
}

static void
clientWriteComplete(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    int done;
    http->out.size += size;
    debug(33, 5) ("clientWriteComplete: FD %d, sz %d, err %d, off %d, len %d\n",
	fd, size, errflag, (int) http->out.offset, objectLen(entry));
    if (size > 0) {
	kb_incr(&Counter.client_http.kbytes_out, size);
	if (isTcpHit(http->log_type))
	    kb_incr(&Counter.client_http.hit_kbytes_out, size);
    }
    if (errflag) {
	/*
	 * just close the socket, httpRequestFree will abort if needed
	 */
	comm_close(fd);
    } else if (NULL == entry) {
	comm_close(fd);		/* yuk */
    } else if (entry->store_status == STORE_ABORTED) {
	comm_close(fd);
    } else if ((done = clientCheckTransferDone(http)) != 0 || size == 0) {
	debug(33, 5) ("clientWriteComplete: FD %d transfer is DONE\n", fd);
	/* We're finished case */
	if (http->entry->mem_obj->reply->content_length < 0) {
	    debug(33, 5) ("clientWriteComplete: closing, content_length < 0\n");
	    comm_close(fd);
	} else if (!done) {
	    debug(33, 5) ("clientWriteComplete: closing, !done\n");
	    comm_close(fd);
	} else if (EBIT_TEST(entry->flag, ENTRY_BAD_LENGTH)) {
	    debug(33, 5) ("clientWriteComplete: closing, ENTRY_BAD_LENGTH\n");
	    comm_close(fd);
	} else if (http->request->flags.proxy_keepalive) {
	    debug(33, 5) ("clientWriteComplete: FD %d Keeping Alive\n", fd);
	    clientKeepaliveNextRequest(http);
	} else {
	    comm_close(fd);
	}
    } else {
	/* More data will be coming from primary server; register with 
	 * storage manager. */
	if (entry->store_status == STORE_ABORTED)
	    debug(33, 0) ("clientWriteComplete 2: entry->swap_status == STORE_ABORTED\n");
	storeClientCopy(entry,
	    http->out.offset,
	    http->out.offset,
	    CLIENT_SOCK_SZ,
	    memAllocate(MEM_CLIENT_SOCK_BUF),
	    clientSendMoreData,
	    http);
    }
}

/*
 * client issued a request with an only-if-cached cache-control directive;
 * we did not find a cached object that can be returned without
 *     contacting other servers;
 * respond with a 504 (Gateway Timeout) as suggested in [RFC 2068]
 */
static void
clientProcessOnlyIfCachedMiss(clientHttpRequest * http)
{
    char *url = http->uri;
    request_t *r = http->request;
    ErrorState *err = NULL;
    debug(33, 4) ("clientProcessOnlyIfCachedMiss: '%s %s'\n",
	RequestMethodStr[r->method], url);
    http->al.http.code = HTTP_GATEWAY_TIMEOUT;
    err = errorCon(ERR_ONLY_IF_CACHED_MISS, HTTP_GATEWAY_TIMEOUT);
    err->request = requestLink(r);
    err->src_addr = http->conn->peer.sin_addr;
    http->entry = clientCreateStoreEntry(http, r->method, null_request_flags);
    errorAppendEntry(http->entry, err);
}

static log_type
clientProcessRequest2(clientHttpRequest * http)
{
    const request_t *r = http->request;
    const cache_key *key;
    StoreEntry *e;
    if (r->method == METHOD_HEAD)
	key = storeKeyPublic(http->uri, METHOD_GET);
    else
	key = storeKeyPublic(http->uri, r->method);
    e = http->entry = storeGet(key);
#if USE_CACHE_DIGESTS
    http->lookup_type = e ? "HIT" : "MISS";
#endif
    if (NULL == e) {
	/* this object isn't in the cache */
	return LOG_TCP_MISS;
    } else if (!storeEntryValidToSend(e)) {
	http->entry = NULL;
	return LOG_TCP_MISS;
    } else if (EBIT_TEST(e->flag, ENTRY_SPECIAL)) {
	/* Special entries are always hits, no matter what the client says */
	http->entry = e;
	return LOG_TCP_HIT;
#if HTTP_VIOLATIONS
    } else if (r->flags.nocache_hack) {
	http->entry = NULL;
	ipcacheReleaseInvalid(r->host);
	return LOG_TCP_CLIENT_REFRESH_MISS;
#endif
    } else if (r->flags.nocache) {
	http->entry = NULL;
	ipcacheReleaseInvalid(r->host);
	return LOG_TCP_CLIENT_REFRESH_MISS;
    } else {
	http->entry = e;
	return LOG_TCP_HIT;
    }
}

static void
clientProcessRequest(clientHttpRequest * http)
{
    char *url = http->uri;
    request_t *r = http->request;
    int fd = http->conn->fd;
    HttpReply *rep;
    debug(33, 4) ("clientProcessRequest: %s '%s'\n",
	RequestMethodStr[r->method],
	url);
    if (r->method == METHOD_CONNECT) {
	http->log_type = LOG_TCP_MISS;
	sslStart(fd, url, r, &http->out.size);
	return;
    } else if (r->method == METHOD_PURGE) {
	clientPurgeRequest(http);
	return;
    } else if (r->method == METHOD_TRACE) {
	if (r->max_forwards == 0) {
	    http->entry = clientCreateStoreEntry(http, r->method, null_request_flags);
	    storeReleaseRequest(http->entry);
	    storeBuffer(http->entry);
	    rep = httpReplyCreate();
	    httpReplySetHeaders(rep, 1.0, HTTP_OK, NULL, "text/plain",
		httpRequestPrefixLen(r), 0, squid_curtime);
	    httpReplySwapOut(rep, http->entry);
	    httpReplyDestroy(rep);
	    httpRequestSwapOut(r, http->entry);
	    storeComplete(http->entry);
	    return;
	}
	/* yes, continue */
	http->log_type = LOG_TCP_MISS;
    } else if (pumpMethod(r->method)) {
	http->log_type = LOG_TCP_MISS;
	/* XXX oof, POST can be cached! */
	pumpInit(fd, r, http->uri);
    } else {
	http->log_type = clientProcessRequest2(http);
    }
    debug(33, 4) ("clientProcessRequest: %s for '%s'\n",
	log_tags[http->log_type],
	http->uri);
    http->out.offset = 0;
    if (NULL != http->entry) {
	storeLockObject(http->entry);
	storeCreateMemObject(http->entry, http->uri, http->log_uri);
	storeClientListAdd(http->entry, http);
#if DELAY_POOLS
	delaySetStoreClient(http->entry, http, http->request->delay_id);
#endif
	http->entry->refcount++;
	storeClientCopy(http->entry,
	    http->out.offset,
	    http->out.offset,
	    CLIENT_SOCK_SZ,
	    memAllocate(MEM_CLIENT_SOCK_BUF),
	    clientCacheHit,
	    http);
    } else {
	/* MISS CASE */
	http->log_type = LOG_TCP_MISS;
	clientProcessMiss(http);
    }
}

/*
 * Prepare to fetch the object as it's a cache miss of some kind.
 */
static void
clientProcessMiss(clientHttpRequest * http)
{
    char *url = http->uri;
    request_t *r = http->request;
    ErrorState *err = NULL;
    debug(33, 4) ("clientProcessMiss: '%s %s'\n",
	RequestMethodStr[r->method], url);
    /*
     * We might have a left-over StoreEntry from a failed cache hit
     * or IMS request.
     */
    if (http->entry) {
	if (EBIT_TEST(http->entry->flag, ENTRY_SPECIAL))
	    debug(33, 0) ("clientProcessMiss: miss on a special object (%s).\n", url);
	storeUnregister(http->entry, http);
	storeUnlockObject(http->entry);
	http->entry = NULL;
    }
    if (clientOnlyIfCached(http)) {
	clientProcessOnlyIfCachedMiss(http);
	return;
    }
    /*
     * Deny loops when running in accelerator/transproxy mode.
     */
    if (http->flags.accel && r->flags.loopdetect) {
	http->al.http.code = HTTP_FORBIDDEN;
	err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	err->request = requestLink(r);
	err->src_addr = http->conn->peer.sin_addr;
	http->entry = clientCreateStoreEntry(http, r->method, null_request_flags);
	errorAppendEntry(http->entry, err);
	return;
    }
    assert(http->out.offset == 0);
    http->entry = clientCreateStoreEntry(http, r->method, r->flags);
    http->entry->refcount++;
    if (http->flags.internal)
	r->protocol = PROTO_INTERNAL;
    fwdStart(http->conn->fd, http->entry, r, http->conn->peer.sin_addr);
}

static clientHttpRequest *
parseHttpRequestAbort(ConnStateData * conn, const char *uri)
{
    clientHttpRequest *http = xcalloc(1, sizeof(clientHttpRequest));
    cbdataAdd(http, MEM_NONE);
    http->conn = conn;
    http->start = current_time;
    http->req_sz = conn->in.offset;
    http->uri = xstrdup(uri);
    http->log_uri = xstrdup(uri);
    http->range_iter.boundary = StringNull;
    return http;
}

/*
 *  parseHttpRequest()
 * 
 *  Returns
 *   NULL on error or incomplete request
 *    a clientHttpRequest structure on success
 */
static clientHttpRequest *
parseHttpRequest(ConnStateData * conn, method_t * method_p, int *status,
    char **prefix_p, size_t * req_line_sz_p)
{
    char *inbuf = NULL;
    char *mstr = NULL;
    char *url = NULL;
    char *req_hdr = NULL;
    float http_ver;
    char *token = NULL;
    char *t = NULL;
    char *end;
    int free_request = 0;
    size_t header_sz;		/* size of headers, not including first line */
    size_t prefix_sz;		/* size of whole request (req-line + headers) */
    size_t url_sz;
    method_t method;
    clientHttpRequest *http = NULL;

    /* Make sure a complete line has been received */
    if ((t = strchr(conn->in.buf, '\n')) == NULL) {
	debug(33, 5) ("Incomplete request line, waiting for more data\n");
	*status = 0;
	*prefix_p = NULL;
	*method_p = METHOD_NONE;
	return NULL;
    }
    *req_line_sz_p = t - conn->in.buf;
    /* Use xmalloc/xmemcpy instead of xstrdup because inbuf might
     * contain NULL bytes; especially for POST data  */
    inbuf = xmalloc(conn->in.offset + 1);
    xmemcpy(inbuf, conn->in.buf, conn->in.offset);
    *(inbuf + conn->in.offset) = '\0';

    /* pre-set these values to make aborting simpler */
    *prefix_p = inbuf;
    *method_p = METHOD_NONE;
    *status = -1;

    /* Look for request method */
    if ((mstr = strtok(inbuf, "\t ")) == NULL) {
	debug(33, 1) ("parseHttpRequest: Can't get request method\n");
	return parseHttpRequestAbort(conn, "error:invalid-request-method");
    }
    method = urlParseMethod(mstr);
    if (method == METHOD_NONE) {
	debug(33, 1) ("parseHttpRequest: Unsupported method '%s'\n", mstr);
	return parseHttpRequestAbort(conn, "error:unsupported-request-method");
    }
    debug(33, 5) ("parseHttpRequest: Method is '%s'\n", mstr);
    *method_p = method;

    /* look for URL */
    if ((url = strtok(NULL, "\r\n\t ")) == NULL) {
	debug(33, 1) ("parseHttpRequest: Missing URL\n");
	return parseHttpRequestAbort(conn, "error:missing-url");
    }
    debug(33, 5) ("parseHttpRequest: Request is '%s'\n", url);

    token = strtok(NULL, null_string);
    for (t = token; t && *t && *t != '\n' && *t != '\r'; t++);
    if (t == NULL || *t == '\0' || t == token || strncasecmp(token, "HTTP/", 5)) {
	debug(33, 3) ("parseHttpRequest: Missing HTTP identifier\n");
#if RELAXED_HTTP_PARSER
	http_ver = (float) 0.9;	/* wild guess */
#else
	return parseHttpRequestAbort(conn, "error:missing-http-ident");
#endif
    } else {
	http_ver = (float) atof(token + 5);
    }

    /* Check if headers are received */
    req_hdr = t;
    header_sz = headersEnd(req_hdr, conn->in.offset - (req_hdr - inbuf));
    if (0 == header_sz) {
	debug(33, 3) ("parseHttpRequest: header_sz == 0\n");
	*status = 0;
	return NULL;
    }
    /*
     * Skip whitespace at the end of the first line, up to the
     * first newline.
     */
    while (isspace(*req_hdr)) {
	header_sz--;
	if (*(req_hdr++) == '\n')
	    break;
    }
    assert(header_sz > 0);
    debug(33, 3) ("parseHttpRequest: req_hdr = {%s}\n", req_hdr);
    end = req_hdr + header_sz;
    debug(33, 3) ("parseHttpRequest: end = {%s}\n", end);

    prefix_sz = end - inbuf;
    *req_line_sz_p = req_hdr - inbuf;
    debug(33, 3) ("parseHttpRequest: prefix_sz = %d, req_line_sz = %d\n",
	(int) prefix_sz, (int) *req_line_sz_p);
    assert(prefix_sz <= conn->in.offset);

    /* Ok, all headers are received */
    http = xcalloc(1, sizeof(clientHttpRequest));
    cbdataAdd(http, MEM_NONE);
    http->http_ver = http_ver;
    http->conn = conn;
    http->start = current_time;
    http->req_sz = prefix_sz;
    http->range_iter.boundary = StringNull;
    *prefix_p = xmalloc(prefix_sz + 1);
    xmemcpy(*prefix_p, conn->in.buf, prefix_sz);
    *(*prefix_p + prefix_sz) = '\0';

    debug(33, 5) ("parseHttpRequest: Request Header is\n%s\n", (*prefix_p) + *req_line_sz_p);
    /* Assign http->uri */
    if ((t = strchr(url, '\n')))	/* remove NL */
	*t = '\0';
    if ((t = strchr(url, '\r')))	/* remove CR */
	*t = '\0';
    if ((t = strchr(url, '#')))	/* remove HTML anchors */
	*t = '\0';

    /* handle internal objects */
    if (internalCheck(url)) {
	/* prepend our name & port */
	http->uri = xstrdup(internalLocalUri(NULL, url));
	http->flags.internal = 1;
    }
    /* see if we running in Config2.Accel.on, if so got to convert it to URL */
    else if (Config2.Accel.on && *url == '/') {
	/* prepend the accel prefix */
	if (opt_accel_uses_host && (t = mime_get_header(req_hdr, "Host"))) {
	    /* If a Host: header was specified, use it to build the URL 
	     * instead of the one in the Config file. */
	    /*
	     * XXX Use of the Host: header here opens a potential
	     * security hole.  There are no checks that the Host: value
	     * corresponds to one of your servers.  It might, for example,
	     * refer to www.playboy.com.  The 'dst' and/or 'dst_domain' ACL 
	     * types should be used to prevent httpd-accelerators 
	     * handling requests for non-local servers */
	    strtok(t, " :/;@");
	    url_sz = strlen(url) + 32 + Config.appendDomainLen +
		strlen(t);
	    http->uri = xcalloc(url_sz, 1);
	    snprintf(http->uri, url_sz, "http://%s:%d%s",
		t, (int) Config.Accel.port, url);
	} else if (vhost_mode) {
	    /* Put the local socket IP address as the hostname */
	    url_sz = strlen(url) + 32 + Config.appendDomainLen;
	    http->uri = xcalloc(url_sz, 1);
	    snprintf(http->uri, url_sz, "http://%s:%d%s",
		inet_ntoa(http->conn->me.sin_addr),
		(int) Config.Accel.port,
		url);
	    debug(33, 5) ("VHOST REWRITE: '%s'\n", http->uri);
	} else {
	    url_sz = strlen(Config2.Accel.prefix) + strlen(url) +
		Config.appendDomainLen + 1;
	    http->uri = xcalloc(url_sz, 1);
	    snprintf(http->uri, url_sz, "%s%s", Config2.Accel.prefix, url);
	}
	http->flags.accel = 1;
    } else {
	/* URL may be rewritten later, so make extra room */
	url_sz = strlen(url) + Config.appendDomainLen + 5;
	http->uri = xcalloc(url_sz, 1);
	strcpy(http->uri, url);
	http->flags.accel = 0;
    }
    http->log_uri = xstrdup(http->uri);
    debug(33, 5) ("parseHttpRequest: Complete request received\n");
    if (free_request)
	safe_free(url);
    xfree(inbuf);
    *status = 1;
    return http;
}

static int
clientReadDefer(int fdnotused, void *data)
{
    ConnStateData *conn = data;
    return conn->defer.until > squid_curtime;
}

static void
clientReadRequest(int fd, void *data)
{
    ConnStateData *conn = data;
    int parser_return_code = 0;
    int k;
    request_t *request = NULL;
    int size;
    method_t method;
    clientHttpRequest *http = NULL;
    clientHttpRequest **H = NULL;
    char *prefix = NULL;
    ErrorState *err = NULL;
    fde *F = &fd_table[fd];
    int len = conn->in.size - conn->in.offset - 1;
    debug(33, 4) ("clientReadRequest: FD %d: reading request...\n", fd);
    Counter.syscalls.sock.reads++;
    size = read(fd, conn->in.buf + conn->in.offset, len);
    if (size > 0) {
	fd_bytes(fd, size, FD_READ);
	kb_incr(&Counter.client_http.kbytes_in, size);
    }
    /*
     * Don't reset the timeout value here.  The timeout value will be
     * set to Config.Timeout.request by httpAccept() and
     * clientWriteComplete(), and should apply to the request as a
     * whole, not individual read() calls.  Plus, it breaks our
     * lame half-close detection
     */
    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
    if (size == 0) {
	if (conn->chr == NULL) {
	    /* no current or pending requests */
	    comm_close(fd);
	    return;
	} else if (!Config.onoff.half_closed_clients) {
	    /* admin doesn't want to support half-closed client sockets */
	    comm_close(fd);
	    return;
	}
	/* It might be half-closed, we can't tell */
	debug(33, 5) ("clientReadRequest: FD %d closed?\n", fd);
	F->flags.socket_eof = 1;
	conn->defer.until = squid_curtime + 1;
	conn->defer.n++;
	fd_note(fd, "half-closed");
	return;
    } else if (size < 0) {
	if (!ignoreErrno(errno)) {
	    debug(50, 2) ("clientReadRequest: FD %d: %s\n", fd, xstrerror());
	    comm_close(fd);
	    return;
	} else if (conn->in.offset == 0) {
	    debug(50, 2) ("clientReadRequest: FD %d: no data to process (%s)\n", fd, xstrerror());
	    return;
	}
	/* Continue to process previously read data */
	size = 0;
    }
    conn->in.offset += size;
    /* Skip leading (and trailing) whitespace */
    while (conn->in.offset > 0) {
	int nrequests;
	size_t req_line_sz;
	while (conn->in.offset > 0 && isspace(conn->in.buf[0])) {
	    xmemmove(conn->in.buf, conn->in.buf + 1, conn->in.offset - 1);
	    conn->in.offset--;
	}
	conn->in.buf[conn->in.offset] = '\0';	/* Terminate the string */
	if (conn->in.offset == 0)
	    break;
	/* Limit the number of concurrent requests to 2 */
	for (H = &conn->chr, nrequests = 0; *H; H = &(*H)->next, nrequests++);
	if (nrequests >= 2) {
	    debug(33, 2) ("clientReadRequest: FD %d max concurrent requests reached\n", fd);
	    debug(33, 5) ("clientReadRequest: FD %d defering new request until one is done\n", fd);
	    conn->defer.until = squid_curtime + 100;	/* Reset when a request is complete */
	    break;
	}
	/* Process request */
	http = parseHttpRequest(conn,
	    &method,
	    &parser_return_code,
	    &prefix,
	    &req_line_sz);
	if (!http)
	    safe_free(prefix);
	if (http) {
	    assert(http->req_sz > 0);
	    conn->in.offset -= http->req_sz;
	    assert(conn->in.offset >= 0);
	    debug(33, 5) ("conn->in.offset = %d\n", (int) conn->in.offset);
	    /*
	     * If we read past the end of this request, move the remaining
	     * data to the beginning
	     */
	    if (conn->in.offset > 0)
		xmemmove(conn->in.buf, conn->in.buf + http->req_sz, conn->in.offset);
	    /* add to the client request queue */
	    for (H = &conn->chr; *H; H = &(*H)->next);
	    *H = http;
	    conn->nrequests++;
	    commSetTimeout(fd, Config.Timeout.lifetime, NULL, NULL);
	    if (parser_return_code < 0) {
		debug(33, 1) ("clientReadRequest: FD %d Invalid Request\n", fd);
		err = errorCon(ERR_INVALID_REQ, HTTP_BAD_REQUEST);
		err->request_hdrs = xstrdup(conn->in.buf);
		http->entry = clientCreateStoreEntry(http, method, null_request_flags);
		errorAppendEntry(http->entry, err);
		safe_free(prefix);
		break;
	    }
	    if ((request = urlParse(method, http->uri)) == NULL) {
		debug(33, 5) ("Invalid URL: %s\n", http->uri);
		err = errorCon(ERR_INVALID_URL, HTTP_BAD_REQUEST);
		err->src_addr = conn->peer.sin_addr;
		err->url = xstrdup(http->uri);
		http->al.http.code = err->http_status;
		http->entry = clientCreateStoreEntry(http, method, null_request_flags);
		errorAppendEntry(http->entry, err);
		safe_free(prefix);
		break;
	    } else {
		/* compile headers */
		/* we should skip request line! */
		if (!httpRequestParseHeader(request, prefix + req_line_sz))
		    debug(33, 1) ("Failed to parse request headers: %s\n%s\n",
			http->uri, prefix);
		/* continue anyway? */
	    }
	    if (!http->flags.internal) {
		if (internalCheck(strBuf(request->urlpath))) {
		    if (0 == strcasecmp(request->host, getMyHostname())) {
			if (request->port == Config.Port.http->i)
			    http->flags.internal = 1;
		    } else if (internalStaticCheck(strBuf(request->urlpath))) {
			xstrncpy(request->host, getMyHostname(), SQUIDHOSTNAMELEN);
			request->port = Config.Port.http->i;
			http->flags.internal = 1;
		    }
		}
	    }
	    safe_free(prefix);
	    safe_free(http->log_uri);
	    http->log_uri = xstrdup(urlCanonicalClean(request));
	    request->client_addr = conn->peer.sin_addr;
	    request->http_ver = http->http_ver;
	    if (!urlCheckRequest(request)) {
		err = errorCon(ERR_UNSUP_REQ, HTTP_NOT_IMPLEMENTED);
		err->src_addr = conn->peer.sin_addr;
		err->request = requestLink(request);
		http->al.http.code = err->http_status;
		http->entry = clientCreateStoreEntry(http, request->method, null_request_flags);
		errorAppendEntry(http->entry, err);
		break;
	    }
	    if (0 == clientCheckContentLength(request)) {
		err = errorCon(ERR_INVALID_REQ, HTTP_LENGTH_REQUIRED);
		err->src_addr = conn->peer.sin_addr;
		err->request = requestLink(request);
		http->al.http.code = err->http_status;
		http->entry = clientCreateStoreEntry(http, request->method, null_request_flags);
		errorAppendEntry(http->entry, err);
		break;
	    }
	    http->request = requestLink(request);
	    /*
	     * break here for NON-GET because most likely there is a
	     * reqeust body following and we don't want to parse it
	     * as though it was new request
	     */
	    if (request->method != METHOD_GET) {
		int cont_len = httpHeaderGetInt(&request->header, HDR_CONTENT_LENGTH);
		int copy_len = XMIN(cont_len, conn->in.offset);
		if (copy_len > 0) {
		    assert(conn->in.offset >= copy_len);
		    request->body_sz = copy_len;
		    request->body = xmalloc(request->body_sz);
		    xmemcpy(request->body, conn->in.buf, request->body_sz);
		    conn->in.offset -= copy_len;
		    if (conn->in.offset)
			xmemmove(conn->in.buf, conn->in.buf + copy_len, conn->in.offset);
		}
		/*
		 * if we didn't get the full body now, then more will
		 * be arriving on the client socket.  Lets cancel
		 * the read handler until this request gets forwarded.
		 */
		if (request->body_sz < cont_len)
		    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
	    }
	    clientAccessCheck(http);
	    continue;		/* while offset > 0 */
	} else if (parser_return_code == 0) {
	    /*
	     *    Partial request received; reschedule until parseHttpRequest()
	     *    is happy with the input
	     */
	    k = conn->in.size - 1 - conn->in.offset;
	    if (k == 0) {
		if (conn->in.offset >= Config.maxRequestSize) {
		    /* The request is too large to handle */
		    debug(33, 0) ("Request won't fit in buffer.\n");
		    debug(33, 0) ("Config 'request_size'= %d bytes.\n",
			Config.maxRequestSize);
		    debug(33, 0) ("This request = %d bytes.\n",
			(int) conn->in.offset);
		    err = errorCon(ERR_INVALID_REQ, HTTP_REQUEST_ENTITY_TOO_LARGE);
		    http->entry = clientCreateStoreEntry(http, request->method, null_request_flags);
		    errorAppendEntry(http->entry, err);
		    return;
		}
		/* Grow the request memory area to accomodate for a large request */
		conn->in.size += REQUEST_BUF_SIZE;
		conn->in.buf = xrealloc(conn->in.buf, conn->in.size);
		/* XXX account conn->in.buf */
		debug(33, 2) ("Handling a large request, offset=%d inbufsize=%d\n",
		    (int) conn->in.offset, conn->in.size);
		k = conn->in.size - 1 - conn->in.offset;
	    }
	    break;
	}
    }
}

/* general lifetime handler for HTTP requests */
static void
requestTimeout(int fd, void *data)
{
    ConnStateData *conn = data;
    ErrorState *err;
    debug(33, 2) ("requestTimeout: FD %d: lifetime is expired.\n", fd);
    if (fd_table[fd].rwstate) {
	/*
	 * Some data has been sent to the client, just close the FD
	 */
	comm_close(fd);
    } else if (conn->nrequests) {
	/*
	 * assume its a persistent connection; just close it
	 */
	comm_close(fd);
    } else {
	/*
	 * Generate an error
	 */
	err = errorCon(ERR_LIFETIME_EXP, HTTP_REQUEST_TIMEOUT);
	err->url = xstrdup("N/A");
	/*
	 * Normally we shouldn't call errorSend() in client_side.c, but
	 * it should be okay in this case.  Presumably if we get here
	 * this is the first request for the connection, and no data
	 * has been written yet
	 */
	assert(conn->chr == NULL);
	errorSend(fd, err);
	/*
	 * if we don't close() here, we still need a timeout handler!
	 */
	commSetTimeout(fd, 30, requestTimeout, conn);
    }
}

static int
httpAcceptDefer(void)
{
    static time_t last_warn = 0;
    if (fdNFree() >= RESERVED_FD)
	return 0;
    if (last_warn + 15 < squid_curtime) {
	debug(33, 0) ("WARNING! Your cache is running out of filedescriptors\n");
	last_warn = squid_curtime;
    }
    return 1;
}

/* Handle a new connection on HTTP socket. */
void
httpAccept(int sock, void *data)
{
    int *N = data;
    int fd = -1;
    ConnStateData *connState = NULL;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    int max = INCOMING_HTTP_MAX;
    commSetSelect(sock, COMM_SELECT_READ, httpAccept, NULL, 0);
    while (max-- && !httpAcceptDefer()) {
	memset(&peer, '\0', sizeof(struct sockaddr_in));
	memset(&me, '\0', sizeof(struct sockaddr_in));
	if ((fd = comm_accept(sock, &peer, &me)) < 0) {
	    if (!ignoreErrno(errno))
		debug(50, 1) ("httpAccept: FD %d: accept failure: %s\n",
		    sock, xstrerror());
	    break;
	}
	debug(33, 4) ("httpAccept: FD %d: accepted\n", fd);
	connState = xcalloc(1, sizeof(ConnStateData));
	connState->peer = peer;
	connState->log_addr = peer.sin_addr;
	connState->log_addr.s_addr &= Config.Addrs.client_netmask.s_addr;
	connState->me = me;
	connState->fd = fd;
	connState->ident.fd = -1;
	connState->in.size = REQUEST_BUF_SIZE;
	connState->in.buf = xcalloc(connState->in.size, 1);
	cbdataAdd(connState, MEM_NONE);
	/* XXX account connState->in.buf */
	comm_add_close_handler(fd, connStateFree, connState);
	if (Config.onoff.log_fqdn)
	    fqdncache_gethostbyaddr(peer.sin_addr, FQDN_LOOKUP_IF_MISS);
	commSetTimeout(fd, Config.Timeout.request, requestTimeout, connState);
	commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, connState, 0);
	commSetDefer(fd, clientReadDefer, connState);
	(*N)++;
    }
}

/* return 1 if the request should be aborted */
static int
CheckQuickAbort2(const clientHttpRequest * http)
{
    int curlen;
    int minlen;
    int expectlen;

    if (!http->request->flags.cachable)
	return 1;
    if (EBIT_TEST(http->entry->flag, KEY_PRIVATE))
	return 1;
    if (http->entry->mem_obj == NULL)
	return 1;
    expectlen = http->entry->mem_obj->reply->content_length;
    curlen = (int) http->entry->mem_obj->inmem_hi;
    minlen = (int) Config.quickAbort.min;
    if (minlen < 0)
	/* disabled */
	return 0;
    if (curlen > expectlen)
	/* bad content length */
	return 1;
    if ((expectlen - curlen) < minlen)
	/* only little more left */
	return 0;
    if ((expectlen - curlen) > Config.quickAbort.max)
	/* too much left to go */
	return 1;
    if (expectlen < 100)
	/* avoid FPE */
	return 0;
    if ((curlen / (expectlen / 100)) > Config.quickAbort.pct)
	/* past point of no return */
	return 0;
    return 1;
}


static void
CheckQuickAbort(clientHttpRequest * http)
{
    StoreEntry *entry = http->entry;
    /* Note, set entry here because http->entry might get changed (for IMS
     * requests) during the storeAbort() call */
    if (entry == NULL)
	return;
    if (storePendingNClients(entry) > 0)
	return;
    if (entry->store_status != STORE_PENDING)
	return;
    if (CheckQuickAbort2(http) == 0)
	return;
    debug(33, 3) ("CheckQuickAbort: ABORTING %s\n", storeUrl(entry));
    storeAbort(entry, 1);
}

#define SENDING_BODY 0
#define SENDING_HDRSONLY 1
static int
clientCheckTransferDone(clientHttpRequest * http)
{
    int sending = SENDING_BODY;
    StoreEntry *entry = http->entry;
    MemObject *mem;
    http_reply *reply;
    int sendlen;
    if (entry == NULL)
	return 0;
    /*
     * For now, 'done_copying' is used for special cases like
     * Range and HEAD requests.
     */
    if (http->flags.done_copying)
	return 1;
    /*
     * Handle STORE_OK and STORE_ABORTED objects.
     * objectLen(entry) will be set proprely.
     */
    if (entry->store_status != STORE_PENDING) {
	if (http->out.offset >= objectLen(entry))
	    return 1;
	else
	    return 0;
    }
    /*
     * Now, handle STORE_PENDING objects
     */
    mem = entry->mem_obj;
    assert(mem != NULL);
    assert(http->request != NULL);
    reply = mem->reply;
    if (reply->hdr_sz == 0)
	return 0;		/* haven't found end of headers yet */
    else if (reply->sline.status == HTTP_OK)
	sending = SENDING_BODY;
    else if (reply->sline.status == HTTP_NO_CONTENT)
	sending = SENDING_HDRSONLY;
    else if (reply->sline.status == HTTP_NOT_MODIFIED)
	sending = SENDING_HDRSONLY;
    else if (reply->sline.status < HTTP_OK)
	sending = SENDING_HDRSONLY;
    else if (http->request->method == METHOD_HEAD)
	sending = SENDING_HDRSONLY;
    else
	sending = SENDING_BODY;
    /*
     * Figure out how much data we are supposed to send.
     * If we are sending a body and we don't have a content-length,
     * then we must wait for the object to become STORE_OK or
     * STORE_ABORTED.
     */
    if (sending == SENDING_HDRSONLY)
	sendlen = reply->hdr_sz;
    else if (reply->content_length < 0)
	return 0;
    else
	sendlen = reply->content_length + reply->hdr_sz;
    /*
     * Now that we have the expected length, did we send it all?
     */
    if (http->out.offset < sendlen)
	return 0;
    else
	return 1;
}

/*
 * This function is designed to serve a fairly specific purpose.
 * Occasionally our vBNS-connected caches can talk to each other, but not
 * the rest of the world.  Here we try to detect frequent failures which
 * make the cache unusable (e.g. DNS lookup and connect() failures).  If
 * the failure:success ratio goes above 1.0 then we go into "hit only"
 * mode where we only return UDP_HIT or UDP_MISS_NOFETCH.  Neighbors
 * will only fetch HITs from us if they are using the ICP protocol.  We
 * stay in this mode for 5 minutes.
 * 
 * Duane W., Sept 16, 1996
 */

static void
checkFailureRatio(err_type etype, hier_code hcode)
{
    static double magic_factor = 100.0;
    double n_good;
    double n_bad;
    if (hcode == HIER_NONE)
	return;
    n_good = magic_factor / (1.0 + request_failure_ratio);
    n_bad = magic_factor - n_good;
    switch (etype) {
    case ERR_DNS_FAIL:
    case ERR_CONNECT_FAIL:
    case ERR_READ_ERROR:
	n_bad++;
	break;
    default:
	n_good++;
    }
    request_failure_ratio = n_bad / n_good;
    if (hit_only_mode_until > squid_curtime)
	return;
    if (request_failure_ratio < 1.0)
	return;
    debug(33, 0) ("Failure Ratio at %4.2f\n", request_failure_ratio);
    debug(33, 0) ("Going into hit-only-mode for %d minutes...\n",
	FAILURE_MODE_TIME / 60);
    hit_only_mode_until = squid_curtime + FAILURE_MODE_TIME;
    request_failure_ratio = 0.8;	/* reset to something less than 1.0 */
}

void
clientHttpConnectionsOpen(void)
{
    ushortlist *u;
    int fd;
    for (u = Config.Port.http; u; u = u->next) {
	enter_suid();
	fd = comm_open(SOCK_STREAM,
	    0,
	    Config.Addrs.tcp_incoming,
	    u->i,
	    COMM_NONBLOCKING,
	    "HTTP Socket");
	leave_suid();
	if (fd < 0)
	    continue;
	comm_listen(fd);
	commSetSelect(fd, COMM_SELECT_READ, httpAccept, NULL, 0);
	/*commSetDefer(fd, httpAcceptDefer, NULL); */
	debug(1, 1) ("Accepting HTTP connections on port %d, FD %d.\n",
	    (int) u->i, fd);
	HttpSockets[NHttpSockets++] = fd;
    }
    if (NHttpSockets < 1)
	fatal("Cannot open HTTP Port");
}

void
clientHttpConnectionsClose(void)
{
    int i;
    for (i = 0; i < NHttpSockets; i++) {
	if (HttpSockets[i] >= 0) {
	    debug(1, 1) ("FD %d Closing HTTP connection\n", HttpSockets[i]);
	    comm_close(HttpSockets[i]);
	    HttpSockets[i] = -1;
	}
    }
    NHttpSockets = 0;
}
