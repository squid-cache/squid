
/*
 * $Id: client_side.cc,v 1.482 2000/05/11 03:15:51 wessels Exp $
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
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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

#if IPF_TRANSPARENT
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <netinet/tcp.h>
#include <net/if.h>
#if HAVE_IP_COMPAT_H
#include <ip_compat.h>
#elif HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#if HAVE_IP_FIL_H
#include <ip_fil.h>
#elif HAVE_NETINET_IP_FIL_H
#include <netinet/ip_fil.h>
#endif
#if HAVE_IP_NAT_H
#include <ip_nat.h>
#elif HAVE_NETINET_IP_NAT_H
#include <netinet/ip_nat.h>
#endif
#endif



#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

static const char *const crlf = "\r\n";

#define REQUEST_BUF_SIZE 4096
#define FAILURE_MODE_TIME 300

/* Local functions */

static CWCB clientWriteComplete;
static CWCB clientWriteBodyComplete;
static PF clientReadRequest;
static PF connStateFree;
static PF requestTimeout;
static int clientCheckTransferDone(clientHttpRequest *);
static int clientGotNotEnough(clientHttpRequest *);
static void checkFailureRatio(err_type, hier_code);
static void clientProcessMiss(clientHttpRequest *);
static void clientBuildReplyHeader(clientHttpRequest * http, HttpReply * rep);
static clientHttpRequest *parseHttpRequestAbort(ConnStateData * conn, const char *uri);
static clientHttpRequest *parseHttpRequest(ConnStateData *, method_t *, int *, char **, size_t *);
static RH clientRedirectDone;
static void clientCheckNoCache(clientHttpRequest *);
static void clientCheckNoCacheDone(int answer, void *data);
static STCB clientHandleIMSReply;
static int clientGetsOldEntry(StoreEntry * new, StoreEntry * old, request_t * request);
static int checkAccelOnly(clientHttpRequest *);
#if USE_IDENT
static IDCB clientIdentDone;
#endif
static int clientOnlyIfCached(clientHttpRequest * http);
static STCB clientSendMoreData;
static STCB clientCacheHit;
static void clientSetKeepaliveFlag(clientHttpRequest *);
static void clientPackRangeHdr(const HttpReply * rep, const HttpHdrRangeSpec * spec, String boundary, MemBuf * mb);
static void clientPackTermBound(String boundary, MemBuf * mb);
static void clientInterpretRequestHeaders(clientHttpRequest *);
static void clientProcessRequest(clientHttpRequest *);
static void clientProcessExpired(void *data);
static void clientProcessOnlyIfCachedMiss(clientHttpRequest * http);
static int clientCachable(clientHttpRequest * http);
static int clientHierarchical(clientHttpRequest * http);
static int clientCheckContentLength(request_t * r);
static int httpAcceptDefer(void);
static log_type clientProcessRequest2(clientHttpRequest * http);
static int clientReplyBodyTooLarge(int clen);
static int clientRequestBodyTooLarge(int clen);

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

#if USE_IDENT
static void
clientIdentDone(const char *ident, void *data)
{
    ConnStateData *conn = data;
    if (ident)
	xstrncpy(conn->ident, ident, sizeof(conn->ident));
    else
	xstrncpy(conn->ident, "-", sizeof(conn->ident));
}
#endif

static aclCheck_t *
clientAclChecklistCreate(const acl_access *acl, const clientHttpRequest *http)
{
    aclCheck_t *ch;
    ConnStateData *conn = http->conn;
    ch = aclChecklistCreate(acl,
	http->request,
	conn->ident);
#if USE_IDENT
    /*
     * hack for ident ACL. It needs to get full addresses, and a
     * place to store the ident result on persistent connections...
     */
    ch->conn = conn;
    cbdataLock(ch->conn);
#endif
    return ch;
}

void
clientAccessCheck(void *data)
{
    clientHttpRequest *http = data;
    if (checkAccelOnly(http)) {
	clientAccessCheckDone(ACCESS_ALLOWED, http);
	return;
    }
    http->acl_checklist = clientAclChecklistCreate(Config.accessList.http, http);
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

StoreEntry *
clientCreateStoreEntry(clientHttpRequest * h, method_t m, request_flags flags)
{
    StoreEntry *e;
    /*
     * For erroneous requests, we might not have a h->request,
     * so make a fake one.
     */
    if (h->request == NULL)
	h->request = requestLink(requestCreate(m, PROTO_NONE, null_string));
    e = storeCreateEntry(h->uri, h->log_uri, flags, m);
    h->sc = storeClientListAdd(e, h);
#if DELAY_POOLS
    delaySetStoreClient(h->sc, delayClient(h->request));
#endif
    storeClientCopy(h->sc, e, 0, 0, CLIENT_SOCK_SZ,
	memAllocate(MEM_CLIENT_SOCK_BUF), clientSendMoreData, h);
    return e;
}

void
clientAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    int page_id = -1;
    http_status status;
    ErrorState *err = NULL;
    debug(33, 2) ("The request %s %s is %s, because it matched '%s'\n",
	RequestMethodStr[http->request->method], http->uri,
	answer == ACCESS_ALLOWED ? "ALLOWED" : "DENIED",
	AclMatchedName ? AclMatchedName : "NO ACL's");
    http->acl_checklist = NULL;
    if (answer == ACCESS_ALLOWED) {
	safe_free(http->uri);
	http->uri = xstrdup(urlCanonical(http->request));
	assert(http->redirect_state == REDIRECT_NONE);
	http->redirect_state = REDIRECT_PENDING;
	redirectStart(http, clientRedirectDone, http);
    } else {
	debug(33, 5) ("Access Denied: %s\n", http->uri);
	debug(33, 5) ("AclMatchedName = %s\n",
	    AclMatchedName ? AclMatchedName : "<null>");
	/*
	 * NOTE: get page_id here, based on AclMatchedName because
	 * if USE_DELAY_POOLS is enabled, then AclMatchedName gets
	 * clobbered in the clientCreateStoreEntry() call
	 * just below.  Pedro Ribeiro <pribeiro@isel.pt>
	 */
	page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName);
	http->log_type = LOG_TCP_DENIED;
	http->entry = clientCreateStoreEntry(http, http->request->method,
	    null_request_flags);
	if (answer == ACCESS_REQ_PROXY_AUTH || aclIsProxyAuth(AclMatchedName)) {
	    if (!http->flags.accel) {
		/* Proxy authorisation needed */
		status = HTTP_PROXY_AUTHENTICATION_REQUIRED;
	    } else {
		/* WWW authorisation needed */
		status = HTTP_UNAUTHORIZED;
	    }
	    if (page_id <= 0)
		page_id = ERR_CACHE_ACCESS_DENIED;
	} else {
	    status = HTTP_FORBIDDEN;
	    if (page_id <= 0)
		page_id = ERR_ACCESS_DENIED;
	}
	err = errorCon(page_id, status);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
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
    if (result) {
	http_status status = atoi(result);
	if (status == 301 || status == 302) {
	    char *t = result;
	    if ((t = strchr(result, ':')) != NULL) {
		http->redirect.status = status;
		http->redirect.location = xstrdup(t + 1);
	    } else {
		debug(33, 1) ("clientRedirectDone: bad input: %s\n", result);
	    }
	}
	if (strcmp(result, http->uri))
	    new_request = urlParse(old_request->method, result);
    }
    if (new_request) {
	safe_free(http->uri);
	http->uri = xstrdup(urlCanonical(new_request));
	new_request->http_ver = old_request->http_ver;
	httpHeaderAppend(&new_request->header, &old_request->header);
	new_request->client_addr = old_request->client_addr;
	new_request->my_addr = old_request->my_addr;
	new_request->my_port = old_request->my_port;
	new_request->flags.redirected = 1;
	if (old_request->body) {
	    new_request->body = xmalloc(old_request->body_sz);
	    xmemcpy(new_request->body, old_request->body, old_request->body_sz);
	    new_request->body_sz = old_request->body_sz;
	}
	new_request->content_length = old_request->content_length;
	requestUnlink(old_request);
	http->request = requestLink(new_request);
    }
    clientInterpretRequestHeaders(http);
#if HEADERS_LOG
    headersLog(0, 1, request->method, request);
#endif
    fd_note(http->conn->fd, http->uri);
    clientCheckNoCache(http);
}

static void
clientCheckNoCache(clientHttpRequest * http)
{
    if (Config.accessList.noCache && http->request->flags.cachable) {
	http->acl_checklist = clientAclChecklistCreate(Config.accessList.noCache, http);
	aclNBCheck(http->acl_checklist, clientCheckNoCacheDone, http);
    } else {
	clientCheckNoCacheDone(http->request->flags.cachable, http);
    }
}

void
clientCheckNoCacheDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    http->request->flags.cachable = answer;
    http->acl_checklist = NULL;
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
    /*
     * Assert that 'http' is already a client of old_entry.  If 
     * it is not, then the beginning of the object data might get
     * freed from memory before we need to access it.
     */
#if STORE_CLIENT_LIST_SEARCH
    assert(storeClientListSearch(http->old_entry->mem_obj, http));
#endif
    entry = storeCreateEntry(url,
	http->log_uri,
	http->request->flags,
	http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    http->sc = storeClientListAdd(entry, http);
#if DELAY_POOLS
    /* delay_id is already set on original store client */
    delaySetStoreClient(http->sc, delayClient(http->request));
#endif
    http->request->lastmod = http->old_entry->lastmod;
    debug(33, 5) ("clientProcessExpired: lastmod %d\n", (int) entry->lastmod);
    http->entry = entry;
    http->out.offset = 0;
    fwdStart(http->conn->fd, http->entry, http->request);
    /* Register with storage manager to receive updates when data comes in. */
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
	debug(33, 0) ("clientProcessExpired: found ENTRY_ABORTED object\n");
    storeClientCopy(http->sc, entry,
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
    /* If the reply is a failure then send the old object as a last
     * resort */
    if (status >= 500 && status < 600) {
	debug(33, 3) ("clientGetsOldEntry: YES, failure reply=%d\n", status);
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
    MemObject *mem;
    const char *url = storeUrl(entry);
    int unlink_request = 0;
    StoreEntry *oldentry;
    int recopy = 1;
    http_status status;
    debug(33, 3) ("clientHandleIMSReply: %s, %d bytes\n", url, (int) size);
    if (entry == NULL) {
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	return;
    }
    if (size < 0 && !EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	return;
    }
    mem = entry->mem_obj;
    status = mem->reply->sline.status;
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	debug(33, 3) ("clientHandleIMSReply: ABORTED '%s'\n", url);
	/* We have an existing entry, but failed to validate it */
	/* Its okay to send the old one anyway */
	http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	storeUnregister(http->sc, entry, http);
	storeUnlockObject(entry);
	entry = http->entry = http->old_entry;
    } else if (STORE_PENDING == entry->store_status && 0 == status) {
	debug(33, 3) ("clientHandleIMSReply: Incomplete headers for '%s'\n", url);
	if (size >= CLIENT_SOCK_SZ) {
	    /* will not get any bigger than that */
	    debug(33, 3) ("clientHandleIMSReply: Reply is too large '%s', using old entry\n", url);
	    /* use old entry, this repeats the code abovez */
	    http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	    storeUnregister(http->sc, entry, http);
	    storeUnlockObject(entry);
	    entry = http->entry = http->old_entry;
	    /* continue */
	} else {
	    storeClientCopy(http->sc, entry,
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
	storeUnregister(http->sc, entry, http);
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
	    httpReplyUpdateOnNotModified(http->old_entry->mem_obj->reply,
		mem->reply);
	    storeTimestampsSet(http->old_entry);
	    http->log_type = LOG_TCP_REFRESH_HIT;
	}
	storeUnregister(http->sc, http->old_entry, http);
	storeUnlockObject(http->old_entry);
	recopy = 0;
    }
    http->old_entry = NULL;	/* done with old_entry */
    assert(!EBIT_TEST(entry->flags, ENTRY_ABORTED));
    if (recopy) {
	storeClientCopy(http->sc, entry,
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
    HttpReply *r;
    debug(33, 1) ("Config2.onoff.enable_purge = %d\n", Config2.onoff.enable_purge);
    if (!Config2.onoff.enable_purge) {
	http->log_type = LOG_TCP_DENIED;
	err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	errorAppendEntry(http->entry, err);
	return;
    }
    http->log_type = LOG_TCP_MISS;
    /* Release both IP and object cache entries */
    ipcacheInvalidate(http->request->host);
    if ((entry = storeGetPublic(http->uri, METHOD_GET)) == NULL) {
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
    if (!EBIT_TEST(e->flags, ENTRY_NEGCACHED))
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
    if (http->log_type == LOG_TCP_HIT)
	Counter.client_http.disk_hits++;
    else if (http->log_type == LOG_TCP_MEM_HIT)
	Counter.client_http.mem_hits++;
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
    case LOG_TCP_OFFLINE_HIT:
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
    StoreEntry *e;
    request_t *request = http->request;
    MemObject *mem = NULL;
    debug(33, 3) ("httpRequestFree: %s\n", storeUrl(http->entry));
    if (!clientCheckTransferDone(http)) {
#if MYSTERIOUS_CODE
	/*
	 * DW: this seems odd here, is it really needed?  It causes
	 * incomplete transfers to get logged with "000" status
	 * code because http->entry becomes NULL.
	 */
	if ((e = http->entry)) {
	    http->entry = NULL;
	    storeUnregister(http->sc, e, http);
	    storeUnlockObject(e);
	}
#endif
	if (http->entry && http->entry->ping_status == PING_WAITING)
	    storeReleaseRequest(http->entry);
    }
    assert(http->log_type < LOG_TYPE_MAX);
    if (http->entry)
	mem = http->entry->mem_obj;
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
	if (request) {
	    Packer p;
	    MemBuf mb;
	    memBufDefInit(&mb);
	    packerToMemInit(&p, &mb);
	    httpHeaderPackInto(&request->header, &p);
	    http->al.http.method = request->method;
	    http->al.http.version = request->http_ver;
	    http->al.headers.request = xstrdup(mb.buf);
	    http->al.hier = request->hier;
	    if (request->user_ident[0])
		http->al.cache.ident = request->user_ident;
	    else
		http->al.cache.ident = conn->ident;
	    packerClean(&p);
	    memBufClean(&mb);
	}
	accessLogLog(&http->al);
	clientUpdateCounters(http);
	clientdbUpdate(conn->peer.sin_addr, http->log_type, PROTO_HTTP, http->out.size);
    }
    if (http->acl_checklist)
	aclChecklistFree(http->acl_checklist);
    if (request)
	checkFailureRatio(request->err_type, http->al.hier.code);
    safe_free(http->uri);
    safe_free(http->log_uri);
    safe_free(http->al.headers.request);
    safe_free(http->al.headers.reply);
    safe_free(http->redirect.location);
    stringClean(&http->range_iter.boundary);
    if ((e = http->entry)) {
	http->entry = NULL;
	storeUnregister(http->sc, e, http);
	storeUnlockObject(e);
    }
    /* old_entry might still be set if we didn't yet get the reply
     * code in clientHandleIMSReply() */
    if ((e = http->old_entry)) {
	http->old_entry = NULL;
	storeUnregister(http->sc, e, http);
	storeUnlockObject(e);
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
    dlinkDelete(&http->active, &ClientActiveRequests);
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
    clientdbEstablished(connState->peer.sin_addr, -1);	/* decrement */
    while ((http = connState->chr) != NULL) {
	assert(http->conn == connState);
	assert(connState->chr != connState->chr->next);
	httpRequestFree(http);
    }
    safe_free(connState->in.buf);
    /* XXX account connState->in.buf */
    pconnHistCount(0, connState->nrequests);
    cbdataFree(connState);
#ifdef _SQUID_LINUX_
    /* prevent those nasty RST packets */
    {
	char buf[SQUID_TCP_SO_RCVBUF];
	while (read(fd, buf, SQUID_TCP_SO_RCVBUF) > 0);
    }
#endif
}

static void
clientInterpretRequestHeaders(clientHttpRequest * http)
{
    request_t *request = http->request;
    const HttpHeader *req_hdr = &request->header;
    int no_cache = 0;
#if USE_USERAGENT_LOG
    const char *str;
#endif
    request->imslen = -1;
    request->ims = httpHeaderGetTime(req_hdr, HDR_IF_MODIFIED_SINCE);
    if (request->ims > 0)
	request->flags.ims = 1;
    if (httpHeaderHas(req_hdr, HDR_PRAGMA)) {
	String s = httpHeaderGetList(req_hdr, HDR_PRAGMA);
	if (strListIsMember(&s, "no-cache", ','))
	    no_cache++;
	stringClean(&s);
    }
    request->cache_control = httpHeaderGetCc(req_hdr);
    if (request->cache_control)
	if (EBIT_TEST(request->cache_control->mask, CC_NO_CACHE))
	    no_cache++;
    if (no_cache) {
#if HTTP_VIOLATIONS
	if (Config.onoff.reload_into_ims)
	    request->flags.nocache_hack = 1;
	else if (refresh_nocache_hack)
	    request->flags.nocache_hack = 1;
	else
#endif
	    request->flags.nocache = 1;
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
    if (httpHeaderHas(req_hdr, HDR_VIA)) {
	String s = httpHeaderGetList(req_hdr, HDR_VIA);
	/*
	 * ThisCache cannot be a member of Via header, "1.0 ThisCache" can.
	 * Note ThisCache2 has a space prepended to the hostname so we don't
	 * accidentally match super-domains.
	 */
	if (strListIsSubstr(&s, ThisCache2, ',')) {
	    debugObj(33, 1, "WARNING: Forwarding loop detected for:\n",
		request, (ObjPackMethod) & httpRequestPack);
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
    if (request->method == METHOD_TRACE) {
	request->max_forwards = httpHeaderGetInt(req_hdr, HDR_MAX_FORWARDS);
    }
    if (clientCachable(http))
	request->flags.cachable = 1;
    if (clientHierarchical(http))
	request->flags.hierarchical = 1;
    debug(33, 5) ("clientInterpretRequestHeaders: REQ_NOCACHE = %s\n",
	request->flags.nocache ? "SET" : "NOT SET");
    debug(33, 5) ("clientInterpretRequestHeaders: REQ_CACHABLE = %s\n",
	request->flags.cachable ? "SET" : "NOT SET");
    debug(33, 5) ("clientInterpretRequestHeaders: REQ_HIERARCHICAL = %s\n",
	request->flags.hierarchical ? "SET" : "NOT SET");
}

/*
 * clientSetKeepaliveFlag() sets request->flags.proxy_keepalive.
 * This is the client-side persistent connection flag.  We need
 * to set this relatively early in the request processing
 * to handle hacks for broken servers and clients.
 */
static void
clientSetKeepaliveFlag(clientHttpRequest * http)
{
    request_t *request = http->request;
    const HttpHeader *req_hdr = &request->header;
    debug(33, 3) ("clientSetKeepaliveFlag: http_ver = %3.1f\n",
	request->http_ver);
    debug(33, 3) ("clientSetKeepaliveFlag: method = %s\n",
	RequestMethodStr[request->method]);
    if (!Config.onoff.client_pconns)
	request->flags.proxy_keepalive = 0;
    else if (httpMsgIsPersistent(request->http_ver, req_hdr))
	request->flags.proxy_keepalive = 1;
}

static int
clientCheckContentLength(request_t * r)
{
    int has_cont_len = (r->content_length >= 0);
    switch (r->method) {
    case METHOD_PUT:
    case METHOD_POST:
	/* PUT/POST requires a request entity */
	return has_cont_len;
    case METHOD_GET:
    case METHOD_HEAD:
	/* We do not want to see a request entity on GET/HEAD requests */
	return !has_cont_len;
    default:
	/* For other types of requests we don't care */
	return 1;
    }
    /* NOT REACHED */
}

static int
clientCachable(clientHttpRequest * http)
{
    const char *url = http->uri;
    request_t *req = http->request;
    method_t method = req->method;
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
    if (code == LOG_TCP_OFFLINE_HIT)
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

/* returns expected content length for multi-range replies
 * note: assumes that httpHdrRangeCanonize has already been called
 * warning: assumes that HTTP headers for individual ranges at the
 *          time of the actuall assembly will be exactly the same as
 *          the headers when clientMRangeCLen() is called */
static int
clientMRangeCLen(clientHttpRequest * http)
{
    int clen = 0;
    HttpHdrRangePos pos = HttpHdrRangeInitPos;
    const HttpHdrRangeSpec *spec;
    MemBuf mb;

    assert(http->entry->mem_obj);

    memBufDefInit(&mb);
    while ((spec = httpHdrRangeGetSpec(http->request->range, &pos))) {

	/* account for headers for this range */
	memBufReset(&mb);
	clientPackRangeHdr(http->entry->mem_obj->reply,
	    spec, http->range_iter.boundary, &mb);
	clen += mb.size;

	/* account for range content */
	clen += spec->length;

	debug(33, 6) ("clientMRangeCLen: (clen += %d + %d) == %d\n",
	    mb.size, spec->length, clen);
    }
    /* account for the terminating boundary */
    memBufReset(&mb);
    clientPackTermBound(http->range_iter.boundary, &mb);
    clen += mb.size;

    memBufClean(&mb);
    return clen;
}

/* adds appropriate Range headers if needed */
static void
clientBuildRangeHeader(clientHttpRequest * http, HttpReply * rep)
{
    HttpHeader *hdr = rep ? &rep->header : 0;
    const char *range_err = NULL;
    request_t *request = http->request;
    int is_hit = isTcpHit(http->log_type);
    assert(request->range);
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
    else if (!request->flags.cachable) /* from we_do_ranges in http.c */
	range_err = "non-cachable request";
    else if (!is_hit && Config.rangeOffsetLimit < httpHdrRangeFirstOffset(request->range)
	    && Config.rangeOffsetLimit != -1) /* from we_do_ranges in http.c */
	range_err = "range outside range_offset_limit";
    /* get rid of our range specs on error */
    if (range_err) {
	debug(33, 3) ("clientBuildRangeHeader: will not do ranges: %s.\n", range_err);
	httpHdrRangeDestroy(http->request->range);
	http->request->range = NULL;
    } else {
	const int spec_count = http->request->range->specs.count;
	int actual_clen = -1;

	debug(33, 3) ("clientBuildRangeHeader: range spec count: %d virgin clen: %d\n",
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
	    /* set new Content-Length to the actual number of bytes
	     * transmitted in the message-body */
	    actual_clen = spec->length;
	} else {
	    /* multipart! */
	    /* generate boundary string */
	    http->range_iter.boundary = httpHdrRangeBoundaryStr(http);
	    /* delete old Content-Type, add ours */
	    httpHeaderDelById(hdr, HDR_CONTENT_TYPE);
	    httpHeaderPutStrf(hdr, HDR_CONTENT_TYPE,
		"multipart/byteranges; boundary=\"%s\"",
		strBuf(http->range_iter.boundary));
	    /* Content-Length is not required in multipart responses
	     * but it is always nice to have one */
	    actual_clen = clientMRangeCLen(http);
	}

	/* replace Content-Length header */
	assert(actual_clen >= 0);
	httpHeaderDelById(hdr, HDR_CONTENT_LENGTH);
	httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, actual_clen);
	debug(33, 3) ("clientBuildRangeHeader: actual content length: %d\n", actual_clen);
    }
}

/*
 * filters out unwanted entries from original reply header
 * adds extra entries if we have more info than origin server
 * adds Squid specific entries
 */
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
     * Add a estimated Age header on cache hits.
     */
    if (is_hit) {
	/*
	 * Remove any existing Age header sent by upstream caches
	 * (note that the existing header is passed along unmodified
	 * on cache misses)
	 */
	httpHeaderDelById(hdr, HDR_AGE);
	/*
	 * This adds the calculated object age. Note that the details of the
	 * age calculation is performed by adjusting the timestamp in
	 * storeTimestampsSet(), not here.
	 *
	 * BROWSER WORKAROUND: IE sometimes hangs when receiving a 0 Age
	 * header, so don't use it unless there is a age to report. Please
	 * note that Age is only used to make a conservative estimation of
	 * the objects age, so a Age: 0 header does not add any useful
	 * information to the reply in any case.
	 */
	if (http->entry->timestamp < squid_curtime)
	    httpHeaderPutInt(hdr, HDR_AGE,
		squid_curtime - http->entry->timestamp);
    }
    /* Append X-Cache */
    httpHeaderPutStrf(hdr, HDR_X_CACHE, "%s from %s",
	is_hit ? "HIT" : "MISS", getMyHostname());
#if USE_CACHE_DIGESTS
    /* Append X-Cache-Lookup: -- temporary hack, to be removed @?@ @?@ */
    httpHeaderPutStrf(hdr, HDR_X_CACHE_LOOKUP, "%s from %s:%d",
	http->lookup_type ? http->lookup_type : "NONE",
	getMyHostname(), ntohs(Config.Sockaddr.http->s.sin_port));
#endif
    if (httpReplyBodySize(request->method, rep) < 0) {
	debug(33, 3) ("clientBuildReplyHeader: can't keep-alive, unknown body size\n");
	request->flags.proxy_keepalive = 0;
    }
    /* Signal keep-alive if needed */
    httpHeaderPutStr(hdr,
	http->flags.accel ? HDR_CONNECTION : HDR_PROXY_CONNECTION,
	request->flags.proxy_keepalive ? "keep-alive" : "close");
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
    size_t k = headersEnd(buf, size);
    if (k && httpReplyParse(rep, buf, k)) {
	/* enforce 1.0 reply version */
	rep->sline.version = 1.0;
	/* do header conversions */
	clientBuildReplyHeader(http, rep);
	/* if we do ranges, change status to "Partial Content" */
	if (http->request->range)
	    httpStatusLineSet(&rep->sline, rep->sline.version,
		HTTP_PARTIAL_CONTENT, NULL);
    } else {
	/* parsing failure, get rid of the invalid reply */
	httpReplyDestroy(rep);
	rep = NULL;
	/* if we were going to do ranges, backoff */
	if (http->request->range) {
	    /* this will fail and destroy request->range */
	    clientBuildRangeHeader(http, rep);
	}
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
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	debug(33, 3) ("clientCacheHit: request aborted\n");
	return;
    } else if (size < 0) {
	/* swap in failure */
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	debug(33, 3) ("clientCacheHit: swapin failure for %s\n", http->uri);
	http->log_type = LOG_TCP_SWAPFAIL_MISS;
	if ((e = http->entry)) {
	    http->entry = NULL;
	    storeUnregister(http->sc, e, http);
	    storeUnlockObject(e);
	}
	clientProcessMiss(http);
	return;
    }
    assert(size > 0);
    mem = e->mem_obj;
    assert(!EBIT_TEST(e->flags, ENTRY_ABORTED));
    if (mem->reply->sline.status == 0) {
	/*
	 * we don't have full reply headers yet; either wait for more or
	 * punt to clientProcessMiss.
	 */
	if (e->mem_status == IN_MEMORY || e->store_status == STORE_OK) {
	    memFree(buf, MEM_CLIENT_SOCK_BUF);
	    clientProcessMiss(http);
	} else if (size == CLIENT_SOCK_SZ && http->out.offset == 0) {
	    memFree(buf, MEM_CLIENT_SOCK_BUF);
	    clientProcessMiss(http);
	} else {
	    debug(33, 3) ("clientCacheHit: waiting for HTTP reply headers\n");
	    storeClientCopy(http->sc, e,
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
    } else if (r->method == METHOD_HEAD) {
	/*
	 * RFC 2068 seems to indicate there is no "conditional HEAD"
	 * request.  We cannot validate a cached object for a HEAD
	 * request, nor can we return 304.
	 */
	if (e->mem_status == IN_MEMORY)
	    http->log_type = LOG_TCP_MEM_HIT;
	clientSendMoreData(data, buf, size);
    } else if (refreshCheckHTTP(e, r) && !http->flags.internal) {
	debug(33, 5) ("clientCacheHit: in refreshCheck() block\n");
	/*
	 * We hold a stale copy; it needs to be validated
	 */
	/*
	 * The 'need_validation' flag is used to prevent forwarding
	 * loops between siblings.  If our copy of the object is stale,
	 * then we should probably only use parents for the validation
	 * request.  Otherwise two siblings could generate a loop if
	 * both have a stale version of the object.
	 */
	r->flags.need_validation = 1;
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
	memFree(buf, MEM_CLIENT_SOCK_BUF);
    } else if (r->flags.ims) {
	/*
	 * Handle If-Modified-Since requests from the client
	 */
	if (mem->reply->sline.status != HTTP_OK) {
	    debug(33, 4) ("clientCacheHit: Reply code %d != 200\n",
		mem->reply->sline.status);
	    memFree(buf, MEM_CLIENT_SOCK_BUF);
	    http->log_type = LOG_TCP_MISS;
	    clientProcessMiss(http);
	} else if (modifiedSince(e, http->request)) {
	    http->log_type = LOG_TCP_IMS_HIT;
	    clientSendMoreData(data, buf, size);
	} else {
	    MemBuf mb = httpPacked304Reply(e->mem_obj->reply);
	    http->log_type = LOG_TCP_IMS_HIT;
	    memFree(buf, MEM_CLIENT_SOCK_BUF);
	    storeUnregister(http->sc, e, http);
	    storeUnlockObject(e);
	    e = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	    http->entry = e;
	    httpReplyParse(e->mem_obj->reply, mb.buf, mb.size);
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
	else if (Config.onoff.offline)
	    http->log_type = LOG_TCP_OFFLINE_HIT;
	clientSendMoreData(data, buf, size);
    }
}

/* put terminating boundary for multiparts */
static void
clientPackTermBound(String boundary, MemBuf * mb)
{
    memBufPrintf(mb, "\r\n--%s--\r\n", strBuf(boundary));
    debug(33, 6) ("clientPackTermBound: buf offset: %d\n", mb->size);
}

/* appends a "part" HTTP header (as in a multi-part/range reply) to the buffer */
static void
clientPackRangeHdr(const HttpReply * rep, const HttpHdrRangeSpec * spec, String boundary, MemBuf * mb)
{
    HttpHeader hdr;
    Packer p;
    assert(rep);
    assert(spec);

    /* put boundary */
    debug(33, 5) ("clientPackRangeHdr: appending boundary: %s\n", strBuf(boundary));
    /* rfc2046 requires to _prepend_ boundary with <crlf>! */
    memBufPrintf(mb, "\r\n--%s\r\n", strBuf(boundary));

    /* stuff the header with required entries and pack it */
    httpHeaderInit(&hdr, hoReply);
    if (httpHeaderHas(&rep->header, HDR_CONTENT_TYPE))
	httpHeaderPutStr(&hdr, HDR_CONTENT_TYPE, httpHeaderGetStr(&rep->header, HDR_CONTENT_TYPE));
    httpHeaderAddContRange(&hdr, *spec, rep->content_length);
    packerToMemInit(&p, mb);
    httpHeaderPackInto(&hdr, &p);
    packerClean(&p);
    httpHeaderClean(&hdr);

    /* append <crlf> (we packed a header, not a reply) */
    memBufPrintf(mb, crlf);
}

/*
 * extracts a "range" from *buf and appends them to mb, updating
 * all offsets and such.
 */
static void
clientPackRange(clientHttpRequest * http,
    HttpHdrRangeIter * i,
    const char **buf,
    ssize_t * size,
    MemBuf * mb)
{
    const ssize_t copy_sz = i->debt_size <= *size ? i->debt_size : *size;
    off_t body_off = http->out.offset - i->prefix_size;
    assert(*size > 0);
    assert(i->spec);
    /*
     * intersection of "have" and "need" ranges must not be empty
     */
    assert(body_off < i->spec->offset + i->spec->length);
    assert(body_off + *size > i->spec->offset);
    /*
     * put boundary and headers at the beginning of a range in a
     * multi-range
     */
    if (http->request->range->specs.count > 1 && i->debt_size == i->spec->length) {
	assert(http->entry->mem_obj);
	clientPackRangeHdr(
	    http->entry->mem_obj->reply,	/* original reply */
	    i->spec,		/* current range */
	    i->boundary,	/* boundary, the same for all */
	    mb
	    );
    }
    /*
     * append content
     */
    debug(33, 3) ("clientPackRange: appending %d bytes\n", copy_sz);
    memBufAppend(mb, *buf, copy_sz);
    /*
     * update offsets
     */
    *size -= copy_sz;
    i->debt_size -= copy_sz;
    body_off += copy_sz;
    *buf += copy_sz;
    http->out.offset = body_off + i->prefix_size;	/* sync */
    /*
     * paranoid check
     */
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
    while (clientCanPackMoreRanges(http, i, size)) {
	off_t start;		/* offset of still missing data */
	assert(i->spec);
	start = i->spec->offset + i->spec->length - i->debt_size;
	debug(33, 3) ("clientPackMoreRanges: in:  offset: %d size: %d\n",
	    (int) body_off, size);
	debug(33, 3) ("clientPackMoreRanges: out: start: %d spec[%d]: [%d, %d), len: %d debt: %d\n",
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
    debug(33, 3) ("clientPackMoreRanges: buf exhausted: in:  offset: %d size: %d need_more: %d\n",
	(int) body_off, size, i->debt_size);
    if (i->debt_size) {
	debug(33, 3) ("clientPackMoreRanges: need more: spec[%d]: [%d, %d), len: %d\n",
	    (int) i->pos, i->spec->offset, (int) (i->spec->offset + i->spec->length), i->spec->length);
	/* skip the data we do not need if possible */
	if (i->debt_size == i->spec->length)	/* at the start of the cur. spec */
	    body_off = i->spec->offset;
	else
	    assert(body_off == i->spec->offset + i->spec->length - i->debt_size);
    } else if (http->request->range->specs.count > 1) {
	/* put terminating boundary for multiparts */
	clientPackTermBound(i->boundary, mb);
    }
    http->out.offset = body_off + i->prefix_size;	/* sync */
    return i->debt_size > 0;
}

static int
clientReplyBodyTooLarge(int clen)
{
    if (0 == Config.maxReplyBodySize)
	return 0;		/* disabled */
    if (clen < 0)
	return 0;		/* unknown */
    if (clen > Config.maxReplyBodySize)
	return 1;		/* too large */
    return 0;
}

static int
clientRequestBodyTooLarge(int clen)
{
    if (0 == Config.maxRequestBodySize)
	return 0;		/* disabled */
    if (clen < 0)
	return 0;		/* unknown, bug? */
    if (clen > Config.maxRequestBodySize)
	return 1;		/* too large */
    return 0;
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
    dlinkDelete(&http->active, &ClientActiveRequests);
    dlinkAdd(http, &http->active, &ClientActiveRequests);
    debug(33, 5) ("clientSendMoreData: FD %d '%s', out.offset=%d \n",
	fd, storeUrl(entry), (int) http->out.offset);
    if (conn->chr != http) {
	/* there is another object in progress, defer this one */
	debug(33, 1) ("clientSendMoreData: Deferring %s\n", storeUrl(entry));
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	return;
    } else if (entry && EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	return;
    } else if (size < 0) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	memFree(buf, MEM_CLIENT_SOCK_BUF);
	return;
    } else if (size == 0) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	memFree(buf, MEM_CLIENT_SOCK_BUF);
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
	if (rep && clientReplyBodyTooLarge(rep->content_length)) {
	    ErrorState *err = errorCon(ERR_TOO_BIG, HTTP_FORBIDDEN);
	    err->request = requestLink(http->request);
	    storeUnregister(http->sc, http->entry, http);
	    storeUnlockObject(http->entry);
	    http->entry = clientCreateStoreEntry(http, http->request->method,
		null_request_flags);
	    errorAppendEntry(http->entry, err);
	    httpReplyDestroy(rep);
	    return;
	} else if (rep) {
	    body_size = size - rep->hdr_sz;
	    assert(body_size >= 0);
	    body_buf = buf + rep->hdr_sz;
	    http->range_iter.prefix_size = rep->hdr_sz;
	    debug(33, 3) ("clientSendMoreData: Appending %d bytes after %d bytes of headers\n",
		body_size, rep->hdr_sz);
	} else if (size < CLIENT_SOCK_SZ && entry->store_status == STORE_PENDING) {
	    /* wait for more to arrive */
	    storeClientCopy(http->sc, entry,
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
    } else if (!http->request->range) {
	/* Avoid copying to MemBuf for non-range requests */
	/* Note, if we're here, then 'rep' is known to be NULL */
	http->out.offset += body_size;
	comm_write(fd, buf, size, clientWriteBodyComplete, http, NULL);
	/* NULL because clientWriteBodyComplete frees it */
	return;
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
#if HEADERS_LOG
	headersLog(0, 0, http->request->method, rep);
#endif
	httpReplyDestroy(rep);
	rep = NULL;
    } else {
	memBufDefInit(&mb);
    }
    /* append body if any */
    if (http->request->range) {
	/* Only GET requests should have ranges */
	assert(http->request->method == METHOD_GET);
	/* clientPackMoreRanges() updates http->out.offset */
	/* force the end of the transfer if we are done */
	if (!clientPackMoreRanges(http, body_buf, body_size, &mb))
	    http->flags.done_copying = 1;
    } else if (body_buf && body_size) {
	http->out.offset += body_size;
	check_size += body_size;
	memBufAppend(&mb, body_buf, body_size);
    }
    if (!http->request->range && http->request->method == METHOD_GET)
	assert(check_size == size);
    /* write */
    comm_write_mbuf(fd, mb, clientWriteComplete, http);
    /* if we don't do it, who will? */
    memFree(buf, MEM_CLIENT_SOCK_BUF);
}

/*
 * clientWriteBodyComplete is called for MEM_CLIENT_SOCK_BUF's
 * written directly to the client socket, versus copying to a MemBuf
 * and going through comm_write_mbuf.  Most non-range responses after
 * the headers probably go through here.
 */
static void
clientWriteBodyComplete(int fd, char *buf, size_t size, int errflag, void *data)
{
    /*
     * NOTE: clientWriteComplete doesn't currently use its "buf"
     * (second) argument, so we pass in NULL.
     */
    clientWriteComplete(fd, NULL, size, errflag, data);
    memFree(buf, MEM_CLIENT_SOCK_BUF);
}

static void
clientKeepaliveNextRequest(clientHttpRequest * http)
{
    ConnStateData *conn = http->conn;
    StoreEntry *entry;
    debug(33, 3) ("clientKeepaliveNextRequest: FD %d\n", conn->fd);
    conn->defer.until = 0;	/* Kick it to read a new request */
    httpRequestFree(http);
    if ((http = conn->chr) == NULL) {
	debug(33, 5) ("clientKeepaliveNextRequest: FD %d reading next req\n",
	    conn->fd);
	fd_note(conn->fd, "Reading next request");
	/*
	 * Set the timeout BEFORE calling clientReadRequest().
	 */
	commSetTimeout(conn->fd, Config.Timeout.pconn, requestTimeout, conn);
	clientReadRequest(conn->fd, conn);	/* Read next request */
	/*
	 * Note, the FD may be closed at this point.
	 */
    } else if ((entry = http->entry) == NULL) {
	/*
	 * this request is in progress, maybe doing an ACL or a redirect,
	 * execution will resume after the operation completes.
	 */
    } else {
	debug(33, 1) ("clientKeepaliveNextRequest: FD %d Sending next\n",
	    conn->fd);
	assert(entry);
	if (0 == storeClientCopyPending(http->sc, entry, http)) {
	    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
		debug(33, 0) ("clientKeepaliveNextRequest: ENTRY_ABORTED\n");
	    storeClientCopy(http->sc, entry,
		http->out.offset,
		http->out.offset,
		CLIENT_SOCK_SZ,
		memAllocate(MEM_CLIENT_SOCK_BUF),
		clientSendMoreData,
		http);
	}
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
	fd, size, errflag, (int) http->out.offset, entry ? objectLen(entry) : 0);
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
    } else if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	comm_close(fd);
    } else if ((done = clientCheckTransferDone(http)) != 0 || size == 0) {
	debug(33, 5) ("clientWriteComplete: FD %d transfer is DONE\n", fd);
	/* We're finished case */
	if (httpReplyBodySize(http->request->method, entry->mem_obj->reply) < 0) {
	    debug(33, 5) ("clientWriteComplete: closing, content_length < 0\n");
	    comm_close(fd);
	} else if (!done) {
	    debug(33, 5) ("clientWriteComplete: closing, !done\n");
	    comm_close(fd);
	} else if (clientGotNotEnough(http)) {
	    debug(33, 5) ("clientWriteComplete: client didn't get all it expected\n");
	    comm_close(fd);
	} else if (http->request->flags.proxy_keepalive) {
	    debug(33, 5) ("clientWriteComplete: FD %d Keeping Alive\n", fd);
	    clientKeepaliveNextRequest(http);
	} else {
	    comm_close(fd);
	}
    } else if (clientReplyBodyTooLarge((int) http->out.offset)) {
	comm_close(fd);
    } else {
	/* More data will be coming from primary server; register with 
	 * storage manager. */
	if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
	    debug(33, 0) ("clientWriteComplete 2: ENTRY_ABORTED\n");
	storeClientCopy(http->sc, entry,
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
    if (http->entry) {
	storeUnregister(http->sc, http->entry, http);
	storeUnlockObject(http->entry);
    }
    http->entry = clientCreateStoreEntry(http, r->method, null_request_flags);
    errorAppendEntry(http->entry, err);
}

static log_type
clientProcessRequest2(clientHttpRequest * http)
{
    request_t *r = http->request;
    StoreEntry *e;
    e = http->entry = storeGetPublic(http->uri, r->method);
    if (r->method == METHOD_HEAD && e == NULL) {
	/* We can generate a HEAD reply from a cached GET object */
	e = http->entry = storeGetPublic(http->uri, METHOD_GET);
    }
    /* Release negatively cached IP-cache entries on reload */
    if (r->flags.nocache)
	ipcacheReleaseInvalid(r->host);
#if HTTP_VIOLATIONS
    else if (r->flags.nocache_hack)
	ipcacheReleaseInvalid(r->host);
#endif
#if USE_CACHE_DIGESTS
    http->lookup_type = e ? "HIT" : "MISS";
#endif
    if (NULL == e) {
	/* this object isn't in the cache */
	debug(33, 3) ("clientProcessRequest2: storeGet() MISS\n");
	return LOG_TCP_MISS;
    }
    if (Config.onoff.offline) {
	debug(33, 3) ("clientProcessRequest2: offline HIT\n");
	http->entry = e;
	return LOG_TCP_HIT;
    }
    if (!storeEntryValidToSend(e)) {
	debug(33, 3) ("clientProcessRequest2: !storeEntryValidToSend MISS\n");
	http->entry = NULL;
	return LOG_TCP_MISS;
    }
    if (EBIT_TEST(e->flags, ENTRY_SPECIAL)) {
	/* Special entries are always hits, no matter what the client says */
	debug(33, 3) ("clientProcessRequest2: ENTRY_SPECIAL HIT\n");
	http->entry = e;
	return LOG_TCP_HIT;
    }
#if HTTP_VIOLATIONS
    if (e->store_status == STORE_PENDING) {
	if (r->flags.nocache || r->flags.nocache_hack) {
	    debug(33, 3) ("Clearing no-cache for STORE_PENDING request\n\t%s\n",
		storeUrl(e));
	    r->flags.nocache = 0;
	    r->flags.nocache_hack = 0;
	}
    }
#endif
    if (r->flags.nocache) {
	debug(33, 3) ("clientProcessRequest2: no-cache REFRESH MISS\n");
	http->entry = NULL;
	ipcacheReleaseInvalid(r->host);
	return LOG_TCP_CLIENT_REFRESH_MISS;
    }
    if (r->range && httpHdrRangeWillBeComplex(r->range)) {
	/*
	 * Some clients break if we return "200 OK" for a Range
	 * request.  We would have to return "200 OK" for a _complex_
	 * Range request that is also a HIT. Thus, let's prevent HITs
	 * on complex Range requests
	 */
	debug(33, 3) ("clientProcessRequest2: complex range MISS\n");
	http->entry = NULL;
	return LOG_TCP_MISS;
    }
    debug(33, 3) ("clientProcessRequest2: default HIT\n");
    http->entry = e;
    return LOG_TCP_HIT;
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
    } else if (r->content_length > 0) {
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
	http->entry->mem_obj->method = r->method;
	http->sc = storeClientListAdd(http->entry, http);
#if DELAY_POOLS
	delaySetStoreClient(http->sc, delayClient(r));
#endif
	storeClientCopy(http->sc, http->entry,
	    http->out.offset,
	    http->out.offset,
	    CLIENT_SOCK_SZ,
	    memAllocate(MEM_CLIENT_SOCK_BUF),
	    clientCacheHit,
	    http);
    } else {
	/* MISS CASE, http->log_type is already set! */
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
	if (EBIT_TEST(http->entry->flags, ENTRY_SPECIAL))
	    debug(33, 0) ("clientProcessMiss: miss on a special object (%s).\n", url);
	storeUnregister(http->sc, http->entry, http);
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
    if (http->redirect.status) {
	HttpReply *rep = httpReplyCreate();
#if LOG_TCP_REDIRECTS
	http->log_type = LOG_TCP_REDIRECT;
#endif
	storeReleaseRequest(http->entry);
	httpRedirectReply(rep, http->redirect.status, http->redirect.location);
	httpReplySwapOut(rep, http->entry);
	httpReplyDestroy(rep);
	storeComplete(http->entry);
	return;
    }
    if (http->flags.internal)
	r->protocol = PROTO_INTERNAL;
    fwdStart(http->conn->fd, http->entry, r);
}

static clientHttpRequest *
parseHttpRequestAbort(ConnStateData * conn, const char *uri)
{
    clientHttpRequest *http = xcalloc(1, sizeof(clientHttpRequest));
    cbdataAdd(http, cbdataXfree, 0);
    http->conn = conn;
    http->start = current_time;
    http->req_sz = conn->in.offset;
    http->uri = xstrdup(uri);
    http->log_uri = xstrndup(uri, MAX_URL);
    http->range_iter.boundary = StringNull;
    dlinkAdd(http, &http->active, &ClientActiveRequests);
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
    size_t req_sz;
    method_t method;
    clientHttpRequest *http = NULL;
#if IPF_TRANSPARENT
    struct natlookup natLookup;
    static int natfd = -1;
#endif

    if ((req_sz = headersEnd(conn->in.buf, conn->in.offset)) == 0) {
	debug(33, 5) ("Incomplete request, waiting for end of headers\n");
	*status = 0;
	*prefix_p = NULL;
	*method_p = METHOD_NONE;
	return NULL;
    }
    assert(req_sz <= conn->in.offset);
    /* Use memcpy, not strdup! */
    inbuf = xmalloc(req_sz + 1);
    xmemcpy(inbuf, conn->in.buf, req_sz);
    *(inbuf + req_sz) = '\0';

    /* pre-set these values to make aborting simpler */
    *prefix_p = inbuf;
    *method_p = METHOD_NONE;
    *status = -1;

    /* Barf on NULL characters in the headers */
    if (strlen(inbuf) != req_sz) {
	debug(33, 1) ("parseHttpRequest: Requestheader contains NULL characters\n");
	return parseHttpRequestAbort(conn, "error:invalid-request");
    }
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

    /* look for URL+HTTP/x.x */
    if ((url = strtok(NULL, "\n")) == NULL) {
	debug(33, 1) ("parseHttpRequest: Missing URL\n");
	return parseHttpRequestAbort(conn, "error:missing-url");
    }
    while (xisspace(*url))
	url++;
    t = url + strlen(url);
    assert(*t == '\0');
    token = NULL;
    while (t > url) {
	t--;
	if (xisspace(*t) && !strncmp(t + 1, "HTTP/", 5)) {
	    token = t + 1;
	    break;
	}
    }
    while (t > url && xisspace(*t))
	*(t--) = '\0';
    debug(33, 5) ("parseHttpRequest: URI is '%s'\n", url);
    if (token == NULL) {
	debug(33, 3) ("parseHttpRequest: Missing HTTP identifier\n");
#if RELAXED_HTTP_PARSER
	http_ver = (float) 0.9;	/* wild guess */
#else
	return parseHttpRequestAbort(conn, "error:missing-http-ident");
#endif
    } else {
	http_ver = (float) atof(token + 5);
    }

    /*
     * Process headers after request line
     */
    req_hdr = strtok(NULL, null_string);
    header_sz = req_sz - (req_hdr - inbuf);
    if (0 == header_sz) {
	debug(33, 3) ("parseHttpRequest: header_sz == 0\n");
	*status = 0;
	return NULL;
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
    cbdataAdd(http, cbdataXfree, 0);
    http->http_ver = http_ver;
    http->conn = conn;
    http->start = current_time;
    http->req_sz = prefix_sz;
    http->range_iter.boundary = StringNull;
    *prefix_p = xmalloc(prefix_sz + 1);
    xmemcpy(*prefix_p, conn->in.buf, prefix_sz);
    *(*prefix_p + prefix_sz) = '\0';
    dlinkAdd(http, &http->active, &ClientActiveRequests);

    debug(33, 5) ("parseHttpRequest: Request Header is\n%s\n", (*prefix_p) + *req_line_sz_p);
    if ((t = strchr(url, '#')))	/* remove HTML anchors */
	*t = '\0';

    /* handle internal objects */
    if (internalCheck(url)) {
	/* prepend our name & port */
	http->uri = xstrdup(internalLocalUri(NULL, url));
	http->flags.internal = 1;
	http->flags.accel = 1;
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
#if IPF_TRANSPARENT
	    natLookup.nl_inport = http->conn->me.sin_port;
	    natLookup.nl_outport = http->conn->peer.sin_port;
	    natLookup.nl_inip = http->conn->me.sin_addr;
	    natLookup.nl_outip = http->conn->peer.sin_addr;
	    natLookup.nl_flags = IPN_TCP;
	    if (natfd < 0)
		natfd = open(IPL_NAT, O_RDONLY, 0);
	    if (natfd < 0) {
		debug(50, 1) ("parseHttpRequest: NAT open failed: %s\n",
		    xstrerror());
		return parseHttpRequestAbort(conn, "error:nat-open-failed");
	    }
	    if (ioctl(natfd, SIOCGNATL, &natLookup) < 0) {
		if (errno != ESRCH) {
		    debug(50, 1) ("parseHttpRequest: NAT lookup failed: ioctl(SIOCGNATL)\n");
		    close(natfd);
		    natfd = -1;
		    return parseHttpRequestAbort(conn, "error:nat-lookup-failed");
		} else
		    snprintf(http->uri, url_sz, "http://%s:%d%s",
			inet_ntoa(http->conn->me.sin_addr),
			(int) Config.Accel.port,
			url);
	    } else
		snprintf(http->uri, url_sz, "http://%s:%d%s",
		    inet_ntoa(natLookup.nl_realip),
		    (int) Config.Accel.port,
		    url);
#else
	    snprintf(http->uri, url_sz, "http://%s:%d%s",
		inet_ntoa(http->conn->me.sin_addr),
		(int) Config.Accel.port,
		url);
#endif
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
    if (!stringHasCntl(http->uri))
	http->log_uri = xstrndup(http->uri, MAX_URL);
    else
	http->log_uri = xstrndup(rfc1738_escape_unescaped(http->uri), MAX_URL);
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
	while (conn->in.offset > 0 && xisspace(conn->in.buf[0])) {
	    xmemmove(conn->in.buf, conn->in.buf + 1, conn->in.offset - 1);
	    conn->in.offset--;
	}
	conn->in.buf[conn->in.offset] = '\0';	/* Terminate the string */
	if (conn->in.offset == 0)
	    break;
	/* Limit the number of concurrent requests to 2 */
	for (H = &conn->chr, nrequests = 0; *H; H = &(*H)->next, nrequests++);
	if (nrequests >= 2) {
	    debug(33, 3) ("clientReadRequest: FD %d max concurrent requests reached\n", fd);
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
	    request->flags.accelerated = http->flags.accel;
	    if (!http->flags.internal) {
		if (internalCheck(strBuf(request->urlpath))) {
		    if (internalHostnameIs(request->host) &&
			request->port == ntohs(Config.Sockaddr.http->s.sin_port)) {
			http->flags.internal = 1;
		    } else if (internalStaticCheck(strBuf(request->urlpath))) {
			xstrncpy(request->host, internalHostname(), SQUIDHOSTNAMELEN);
			request->port = ntohs(Config.Sockaddr.http->s.sin_port);
			http->flags.internal = 1;
		    }
		}
	    }
	    /*
	     * cache the Content-length value in request_t.
	     */
	    request->content_length = httpHeaderGetInt(&request->header,
		HDR_CONTENT_LENGTH);
	    request->flags.internal = http->flags.internal;
	    safe_free(prefix);
	    safe_free(http->log_uri);
	    http->log_uri = xstrdup(urlCanonicalClean(request));
	    request->client_addr = conn->peer.sin_addr;
	    request->my_addr = conn->me.sin_addr;
	    request->my_port = ntohs(conn->me.sin_port);
	    request->http_ver = http->http_ver;
	    if (!urlCheckRequest(request)) {
		err = errorCon(ERR_UNSUP_REQ, HTTP_NOT_IMPLEMENTED);
		err->src_addr = conn->peer.sin_addr;
		err->request = requestLink(request);
		request->flags.proxy_keepalive = 0;
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
	     * We need to set the keepalive flag before doing some
	     * hacks for POST/PUT requests below.  Maybe we could
	     * set keepalive flag even earlier.
	     */
	    clientSetKeepaliveFlag(http);
	    /*
	     * break here if the request has a content-length
	     * because there is a reqeust body following and we
	     * don't want to parse it as though it was new request.
	     */
	    if (request->content_length >= 0) {
		int copy_len = XMIN(conn->in.offset, request->content_length);
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
		if (request->body_sz < request->content_length)
		    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
		if (request->content_length < 0)
		    (void) 0;
		else if (clientRequestBodyTooLarge(request->content_length)) {
		    err = errorCon(ERR_TOO_BIG, HTTP_REQUEST_ENTITY_TOO_LARGE);
		    err->request = requestLink(request);
		    http->entry = clientCreateStoreEntry(http,
			METHOD_NONE, null_request_flags);
		    errorAppendEntry(http->entry, err);
		    break;
		}
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
		if (conn->in.offset >= Config.maxRequestHeaderSize) {
		    /* The request is too large to handle */
		    debug(33, 1) ("Request header is too large (%d bytes)\n",
			(int) conn->in.offset);
		    debug(33, 1) ("Config 'request_header_max_size'= %d bytes.\n",
			Config.maxRequestHeaderSize);
		    err = errorCon(ERR_TOO_BIG, HTTP_REQUEST_ENTITY_TOO_LARGE);
		    http = parseHttpRequestAbort(conn, "error:request-too-large");
		    /* add to the client request queue */
		    for (H = &conn->chr; *H; H = &(*H)->next);
		    *H = http;
		    http->entry = clientCreateStoreEntry(http, METHOD_NONE, null_request_flags);
		    errorAppendEntry(http->entry, err);
		    return;
		}
		/* Grow the request memory area to accomodate for a large request */
		conn->in.size += REQUEST_BUF_SIZE;
		conn->in.buf = xrealloc(conn->in.buf, conn->in.size);
		/* XXX account conn->in.buf */
		debug(33, 3) ("Handling a large request, offset=%d inbufsize=%d\n",
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
    debug(33, 3) ("requestTimeout: FD %d: lifetime is expired.\n", fd);
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
	/*
	 * Aha, but we don't want a read handler!
	 */
	commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
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
#if USE_IDENT
    static aclCheck_t identChecklist;
#endif
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
	connState = memAllocate(MEM_CONNSTATEDATA);
	connState->peer = peer;
	connState->log_addr = peer.sin_addr;
	connState->log_addr.s_addr &= Config.Addrs.client_netmask.s_addr;
	connState->me = me;
	connState->fd = fd;
	connState->in.size = REQUEST_BUF_SIZE;
	connState->in.buf = xcalloc(connState->in.size, 1);
	cbdataAdd(connState, memFree, MEM_CONNSTATEDATA);
	/* XXX account connState->in.buf */
	comm_add_close_handler(fd, connStateFree, connState);
	if (Config.onoff.log_fqdn)
	    fqdncache_gethostbyaddr(peer.sin_addr, FQDN_LOOKUP_IF_MISS);
	commSetTimeout(fd, Config.Timeout.request, requestTimeout, connState);
#if USE_IDENT
	identChecklist.src_addr = peer.sin_addr;
	identChecklist.my_addr = me.sin_addr;
	identChecklist.my_port = ntohs(me.sin_port);
	if (aclCheckFast(Config.accessList.identLookup, &identChecklist))
	    identStart(&me, &peer, clientIdentDone, connState);
#endif
	commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, connState, 0);
	commSetDefer(fd, clientReadDefer, connState);
	clientdbEstablished(peer.sin_addr, 1);
	assert(N);
	(*N)++;
    }
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
     * Handle STORE_OK objects.
     * objectLen(entry) will be set proprely.
     */
    if (entry->store_status == STORE_OK) {
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
     * then we must wait for the object to become STORE_OK.
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

static int
clientGotNotEnough(clientHttpRequest * http)
{
    int cl = httpReplyBodySize(http->request->method, http->entry->mem_obj->reply);
    int hs = http->entry->mem_obj->reply->hdr_sz;
    assert(cl >= 0);
    if (http->out.offset < cl + hs)
	return 1;
    return 0;
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
    sockaddr_in_list *s;
    int fd;
    for (s = Config.Sockaddr.http; s; s = s->next) {
	enter_suid();
	fd = comm_open(SOCK_STREAM,
	    0,
	    s->s.sin_addr,
	    ntohs(s->s.sin_port),
	    COMM_NONBLOCKING,
	    "HTTP Socket");
	leave_suid();
	if (fd < 0)
	    continue;
	comm_listen(fd);
	commSetSelect(fd, COMM_SELECT_READ, httpAccept, NULL, 0);
	/*commSetDefer(fd, httpAcceptDefer, NULL); */
	debug(1, 1) ("Accepting HTTP connections at %s, port %d, FD %d.\n",
	    inet_ntoa(s->s.sin_addr),
	    (int) ntohs(s->s.sin_port),
	    fd);
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
