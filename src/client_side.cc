
/*
 * $Id: client_side.cc,v 1.586 2002/08/22 20:26:38 wessels Exp $
 *
 * DEBUG: section 33    Client-side Routines
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

#if IPF_TRANSPARENT
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <netinet/tcp.h>
#include <net/if.h>
#if HAVE_IP_FIL_COMPAT_H
#include <ip_fil_compat.h>
#elif HAVE_NETINET_IP_FIL_COMPAT_H
#include <netinet/ip_fil_compat.h>
#elif HAVE_IP_COMPAT_H
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

#if PF_TRANSPARENT
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#endif

#if LINUX_NETFILTER
#include <linux/netfilter_ipv4.h>
#endif


#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

static const char *const crlf = "\r\n";

#define FAILURE_MODE_TIME 300

/* Local functions */

static CWCB clientWriteComplete;
static CWCB clientWriteBodyComplete;
static PF clientReadRequest;
static PF connStateFree;
static PF requestTimeout;
static PF clientLifetimeTimeout;
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
static void clientInterpretRequestHeaders(clientHttpRequest *);
static void clientProcessRequest(clientHttpRequest *);
static void clientProcessExpired(void *data);
static void clientProcessOnlyIfCachedMiss(clientHttpRequest * http);
static int clientCachable(clientHttpRequest * http);
static int clientHierarchical(clientHttpRequest * http);
static int clientCheckContentLength(request_t * r);
static DEFER httpAcceptDefer;
static log_type clientProcessRequest2(clientHttpRequest * http);
static int clientReplyBodyTooLarge(HttpReply *, ssize_t clen);
static int clientRequestBodyTooLarge(int clen);
static void clientProcessBody(ConnStateData * conn);

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
    if (http->request->method == METHOD_PURGE)
	return 0;
    return 1;
}

#if USE_IDENT
static void
clientIdentDone(const char *ident, void *data)
{
    ConnStateData *conn = data;
    xstrncpy(conn->rfc931, ident ? ident : dash_str, USER_IDENT_SZ);
}

#endif

static aclCheck_t *
clientAclChecklistCreate(const acl_access * acl, const clientHttpRequest * http)
{
    aclCheck_t *ch;
    ConnStateData *conn = http->conn;
    ch = aclChecklistCreate(acl,
	http->request,
	conn->rfc931);

    /*
     * hack for ident ACL. It needs to get full addresses, and a
     * place to store the ident result on persistent connections...
     */
    /* connection oriented auth also needs these two lines for it's operation. */
    ch->conn = cbdataReference(conn);	/* unreferenced in acl.c */

    return ch;
}

void
clientAccessCheck(void *data)
{
    clientHttpRequest *http = data;
    if (checkAccelOnly(http)) {
	/* deny proxy requests in accel_only mode */
	debug(33, 1) ("clientAccessCheck: proxy request denied in accel_only mode\n");
	clientAccessCheckDone(ACCESS_DENIED, http);
	return;
    }
    http->acl_checklist = clientAclChecklistCreate(Config.accessList.http, http);
    aclNBCheck(http->acl_checklist, clientAccessCheckDone, http);
}

/*
 * returns true if client specified that the object must come from the cache
 * without contacting origin server
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
    delaySetStoreClient(h->sc, delayClient(h));
#endif
    h->reqofs = 0;
    h->reqsize = 0;
    /* I don't think this is actually needed! -- adrian */
    /* h->reqbuf = h->norm_reqbuf; */
    assert(h->reqbuf == h->norm_reqbuf);
    storeClientCopy(h->sc, e, 0, HTTP_REQBUF_SZ, h->reqbuf,
	clientSendMoreData, h);
    return e;
}

void
clientAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    err_type page_id;
    http_status status;
    ErrorState *err = NULL;
    char *proxy_auth_msg = NULL;
    debug(33, 2) ("The request %s %s is %s, because it matched '%s'\n",
	RequestMethodStr[http->request->method], http->uri,
	answer == ACCESS_ALLOWED ? "ALLOWED" : "DENIED",
	AclMatchedName ? AclMatchedName : "NO ACL's");
    proxy_auth_msg = authenticateAuthUserRequestMessage(http->conn->auth_user_request ? http->conn->auth_user_request : http->request->auth_user_request);
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
	debug(33, 5) ("Proxy Auth Message = %s\n",
	    proxy_auth_msg ? proxy_auth_msg : "<null>");
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
	    if (page_id == ERR_NONE)
		page_id = ERR_CACHE_ACCESS_DENIED;
	} else {
	    status = HTTP_FORBIDDEN;
	    if (page_id == ERR_NONE)
		page_id = ERR_ACCESS_DENIED;
	}
	err = errorCon(page_id, status);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	if (http->conn->auth_user_request)
	    err->auth_user_request = http->conn->auth_user_request;
	else if (http->request->auth_user_request)
	    err->auth_user_request = http->request->auth_user_request;
	/* lock for the error state */
	if (err->auth_user_request)
	    authenticateAuthUserRequestLock(err->auth_user_request);
	err->callback_data = NULL;
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
	http_status status = (http_status) atoi(result);
	if (status == HTTP_MOVED_PERMANENTLY || status == HTTP_MOVED_TEMPORARILY) {
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
	if (old_request->auth_user_request) {
	    new_request->auth_user_request = old_request->auth_user_request;
	    authenticateAuthUserRequestLock(new_request->auth_user_request);
	}
	if (old_request->body_connection) {
	    new_request->body_connection = old_request->body_connection;
	    old_request->body_connection = NULL;
	}
	new_request->content_length = old_request->content_length;
	new_request->flags.proxy_keepalive = old_request->flags.proxy_keepalive;
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
    http->old_sc = http->sc;
    http->old_reqsize = http->reqsize;
    http->old_reqofs = http->reqofs;
    http->reqbuf = http->ims_reqbuf;
#if STORE_CLIENT_LIST_DEBUG
    /*
     * Assert that 'http' is already a client of old_entry.  If 
     * it is not, then the beginning of the object data might get
     * freed from memory before we need to access it.
     */
    assert(http->sc->owner == http);
#endif
    entry = storeCreateEntry(url,
	http->log_uri,
	http->request->flags,
	http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    http->sc = storeClientListAdd(entry, http);
#if DELAY_POOLS
    /* delay_id is already set on original store client */
    delaySetStoreClient(http->sc, delayClient(http));
#endif
    http->request->lastmod = http->old_entry->lastmod;
    debug(33, 5) ("clientProcessExpired: lastmod %ld\n", (long int) entry->lastmod);
    http->entry = entry;
    http->out.offset = 0;
    fwdStart(http->conn->fd, http->entry, http->request);
    /* Register with storage manager to receive updates when data comes in. */
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
	debug(33, 0) ("clientProcessExpired: found ENTRY_ABORTED object\n");
    http->reqofs = 0;
    storeClientCopy(http->sc, entry,
	http->out.offset,
	HTTP_REQBUF_SZ,
	http->reqbuf,
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
	debug(33, 5) ("clientGetsOldEntry: YES, modified since %ld\n",
	    (long int) request->ims);
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
    http_status status;
    debug(33, 3) ("clientHandleIMSReply: %s, %ld bytes\n", url, (long int) size);
    if (entry == NULL) {
	return;
    }
    if (size < 0 && !EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	return;
    }
    /* update size of the request */
    http->reqsize = size + http->reqofs;
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
	http->sc = http->old_sc;
	http->reqbuf = http->norm_reqbuf;
	http->reqofs = http->old_reqofs;
	http->reqsize = http->old_reqsize;
    } else if (STORE_PENDING == entry->store_status && 0 == status) {
	debug(33, 3) ("clientHandleIMSReply: Incomplete headers for '%s'\n", url);
	if (size + http->reqofs >= HTTP_REQBUF_SZ) {
	    /* will not get any bigger than that */
	    debug(33, 3) ("clientHandleIMSReply: Reply is too large '%s', using old entry\n", url);
	    /* use old entry, this repeats the code abovez */
	    http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	    storeUnregister(http->sc, entry, http);
	    storeUnlockObject(entry);
	    entry = http->entry = http->old_entry;
	    http->sc = http->old_sc;
	    http->reqbuf = http->norm_reqbuf;
	    http->reqofs = http->old_reqofs;
	    http->reqsize = http->old_reqsize;
	    /* continue */
	} else {
	    http->reqofs += size;
	    storeClientCopy(http->sc, entry,
		http->out.offset + http->reqofs,
		HTTP_REQBUF_SZ - http->reqofs,
		http->reqbuf + http->reqofs,
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
	http->sc = http->old_sc;
	storeUnlockObject(entry);
	entry = http->entry = oldentry;
	entry->timestamp = squid_curtime;
	if (unlink_request) {
	    requestUnlink(entry->mem_obj->request);
	    entry->mem_obj->request = NULL;
	}
	http->reqbuf = http->norm_reqbuf;
	http->reqofs = http->old_reqofs;
	http->reqsize = http->old_reqsize;
    } else {
	/* the client can handle this reply, whatever it is */
	http->log_type = LOG_TCP_REFRESH_MISS;
	if (HTTP_NOT_MODIFIED == mem->reply->sline.status) {
	    httpReplyUpdateOnNotModified(http->old_entry->mem_obj->reply,
		mem->reply);
	    storeTimestampsSet(http->old_entry);
	    http->log_type = LOG_TCP_REFRESH_HIT;
	}
	storeUnregister(http->old_sc, http->old_entry, http);
	storeUnlockObject(http->old_entry);
    }
    http->old_entry = NULL;	/* done with old_entry */
    http->old_sc = NULL;
    http->old_reqofs = 0;
    http->old_reqsize = 0;
    assert(!EBIT_TEST(entry->flags, ENTRY_ABORTED));

    clientSendMoreData(data, http->reqbuf, http->reqsize);
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
    debug(33, 3) ("modifiedSince: mod_time = %ld\n", (long int) mod_time);
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
    http_status status = HTTP_NOT_FOUND;
    http_version_t version;
    debug(33, 3) ("Config2.onoff.enable_purge = %d\n", Config2.onoff.enable_purge);
    if (!Config2.onoff.enable_purge) {
	http->log_type = LOG_TCP_DENIED;
	err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	errorAppendEntry(http->entry, err);
	return;
    }
    /* Release both IP cache */
    ipcacheInvalidate(http->request->host);

    if (!http->flags.purging) {
	/* Try to find a base entry */
	http->flags.purging = 1;
	entry = storeGetPublicByRequestMethod(http->request, METHOD_GET);
	if (!entry)
	    entry = storeGetPublicByRequestMethod(http->request, METHOD_HEAD);
	if (entry) {
	    /* Swap in the metadata */
	    http->entry = entry;
	    storeLockObject(http->entry);
	    storeCreateMemObject(http->entry, http->uri, http->log_uri);
	    http->entry->mem_obj->method = http->request->method;
	    http->sc = storeClientListAdd(http->entry, http);
	    http->log_type = LOG_TCP_HIT;
	    http->reqofs = 0;
	    storeClientCopy(http->sc, http->entry,
		http->out.offset,
		HTTP_REQBUF_SZ,
		http->reqbuf,
		clientCacheHit,
		http);
	    return;
	}
    }
    http->log_type = LOG_TCP_MISS;
    /* Release the cached URI */
    entry = storeGetPublicByRequestMethod(http->request, METHOD_GET);
    if (entry) {
	debug(33, 4) ("clientPurgeRequest: GET '%s'\n",
	    storeUrl(entry));
	storeRelease(entry);
	status = HTTP_OK;
    }
    entry = storeGetPublicByRequestMethod(http->request, METHOD_HEAD);
    if (entry) {
	debug(33, 4) ("clientPurgeRequest: HEAD '%s'\n",
	    storeUrl(entry));
	storeRelease(entry);
	status = HTTP_OK;
    }
    /* And for Vary, release the base URI if none of the headers was included in the request */
    if (http->request->vary_headers && !strstr(http->request->vary_headers, "=")) {
	entry = storeGetPublic(urlCanonical(http->request), METHOD_GET);
	if (entry) {
	    debug(33, 4) ("clientPurgeRequest: Vary GET '%s'\n",
		storeUrl(entry));
	    storeRelease(entry);
	    status = HTTP_OK;
	}
	entry = storeGetPublic(urlCanonical(http->request), METHOD_HEAD);
	if (entry) {
	    debug(33, 4) ("clientPurgeRequest: Vary HEAD '%s'\n",
		storeUrl(entry));
	    storeRelease(entry);
	    status = HTTP_OK;
	}
    }
    /*
     * Make a new entry to hold the reply to be written
     * to the client.
     */
    http->entry = clientCreateStoreEntry(http, http->request->method, null_request_flags);
    httpReplyReset(r = http->entry->mem_obj->reply);
    httpBuildVersion(&version, 1, 0);
    httpReplySetHeaders(r, version, status, NULL, NULL, 0, 0, -1);
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

static void
clientUpdateCounters(clientHttpRequest * http)
{
    int svc_time = tvSubMsec(http->start, current_time);
    ping_data *i;
    HierarchyLogEntry *H;
    statCounter.client_http.requests++;
    if (isTcpHit(http->log_type))
	statCounter.client_http.hits++;
    if (http->log_type == LOG_TCP_HIT)
	statCounter.client_http.disk_hits++;
    else if (http->log_type == LOG_TCP_MEM_HIT)
	statCounter.client_http.mem_hits++;
    if (http->request->err_type != ERR_NONE)
	statCounter.client_http.errors++;
    statHistCount(&statCounter.client_http.all_svc_time, svc_time);
    /*
     * The idea here is not to be complete, but to get service times
     * for only well-defined types.  For example, we don't include
     * LOG_TCP_REFRESH_FAIL_HIT because its not really a cache hit
     * (we *tried* to validate it, but failed).
     */
    switch (http->log_type) {
    case LOG_TCP_REFRESH_HIT:
	statHistCount(&statCounter.client_http.nh_svc_time, svc_time);
	break;
    case LOG_TCP_IMS_HIT:
	statHistCount(&statCounter.client_http.nm_svc_time, svc_time);
	break;
    case LOG_TCP_HIT:
    case LOG_TCP_MEM_HIT:
    case LOG_TCP_OFFLINE_HIT:
	statHistCount(&statCounter.client_http.hit_svc_time, svc_time);
	break;
    case LOG_TCP_MISS:
    case LOG_TCP_CLIENT_REFRESH_MISS:
	statHistCount(&statCounter.client_http.miss_svc_time, svc_time);
	break;
    default:
	/* make compiler warnings go away */
	break;
    }
    H = &http->request->hier;
    switch (H->alg) {
    case PEER_SA_DIGEST:
	statCounter.cd.times_used++;
	break;
    case PEER_SA_ICP:
	statCounter.icp.times_used++;
	i = &H->ping;
	if (0 != i->stop.tv_sec && 0 != i->start.tv_sec)
	    statHistCount(&statCounter.icp.query_svc_time,
		tvSubUsec(i->start, i->stop));
	if (i->timeout)
	    statCounter.icp.query_timeouts++;
	break;
    case PEER_SA_NETDB:
	statCounter.netdb.times_used++;
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
	if (request && request->body_connection)
	    clientAbortBody(request);	/* abort body transter */
	/* HN: This looks a bit odd.. why should client_side care about
	 * the ICP selection status?
	 */
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
	    if (request->auth_user_request) {
		http->al.cache.authuser = xstrdup(authenticateUserRequestUsername(request->auth_user_request));
		authenticateAuthUserRequestUnlock(request->auth_user_request);
		request->auth_user_request = NULL;
	    }
	    if (conn->rfc931[0])
		http->al.cache.rfc931 = conn->rfc931;
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
    safe_free(http->al.cache.authuser);
    safe_free(http->redirect.location);
    if ((e = http->entry)) {
	http->entry = NULL;
	storeUnregister(http->sc, e, http);
	http->sc = NULL;
	storeUnlockObject(e);
    }
    /* old_entry might still be set if we didn't yet get the reply
     * code in clientHandleIMSReply() */
    if ((e = http->old_entry)) {
	http->old_entry = NULL;
	storeUnregister(http->old_sc, e, http);
	http->old_sc = NULL;
	storeUnlockObject(e);
    }
    requestUnlink(http->request);
    assert(http != http->next);
    assert(http->conn->chr != NULL);
    /* Unlink us from the clients request list */
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
    if (connState->auth_user_request)
	authenticateAuthUserRequestUnlock(connState->auth_user_request);
    connState->auth_user_request = NULL;
    authenticateOnCloseConnection(connState);
    memFreeBuf(connState->in.size, connState->in.buf);
    pconnHistCount(0, connState->nrequests);
    cbdataFree(connState);
#ifdef _SQUID_LINUX_
    /* prevent those nasty RST packets */
    {
	char buf[SQUID_TCP_SO_RCVBUF];
	while (FD_READ_METHOD(fd, buf, SQUID_TCP_SO_RCVBUF) > 0);
    }
#endif
}

static void
clientInterpretRequestHeaders(clientHttpRequest * http)
{
    request_t *request = http->request;
    const HttpHeader *req_hdr = &request->header;
    int no_cache = 0;
    const char *str;
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
    /* Work around for supporting the Reload button in IE browsers
     * when Squid is used as an accelerator or transparent proxy,
     * by turning accelerated IMS request to no-cache requests.
     * Now knows about IE 5.5 fix (is actually only fixed in SP1, 
     * but we can't tell whether we are talking to SP1 or not so 
     * all 5.5 versions are treated 'normally').
     */
    if (Config.onoff.ie_refresh) {
	if (http->flags.accel && request->flags.ims) {
	    if ((str = httpHeaderGetStr(req_hdr, HDR_USER_AGENT))) {
		if (strstr(str, "MSIE 5.01") != NULL)
		    no_cache++;
		else if (strstr(str, "MSIE 5.0") != NULL)
		    no_cache++;
		else if (strstr(str, "MSIE 4.") != NULL)
		    no_cache++;
		else if (strstr(str, "MSIE 3.") != NULL)
		    no_cache++;
	    }
	}
    }
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
	/*
	 * Since we're not doing ranges atm, just set the flag if
	 * the header exists, and then free the range header info
	 * -- adrian
	 */
	request->range = httpHeaderGetRange(req_hdr);
	if (request->range) {
	    request->flags.range = 1;
	    httpHdrRangeDestroy(request->range);
	    request->range = NULL;
	}
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
#if USE_REFERER_LOG
    if ((str = httpHeaderGetStr(req_hdr, HDR_REFERER)))
	logReferer(fqdnFromAddr(http->conn->peer.sin_addr), str,
	    http->log_uri);
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
    debug(33, 3) ("clientSetKeepaliveFlag: http_ver = %d.%d\n",
	request->http_ver.major, request->http_ver.minor);
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
    switch (r->method) {
    case METHOD_PUT:
    case METHOD_POST:
	/* PUT/POST requires a request entity */
	return (r->content_length >= 0);
    case METHOD_GET:
    case METHOD_HEAD:
	/* We do not want to see a request entity on GET/HEAD requests */
	return (r->content_length <= 0);
    default:
	/* For other types of requests we don't care */
	return 1;
    }
    /* NOT REACHED */
}

static int
clientCachable(clientHttpRequest * http)
{
    request_t *req = http->request;
    method_t method = req->method;
    if (req->protocol == PROTO_HTTP)
	return httpCachable(method);
    /* FTP is always cachable */
    if (req->protocol == PROTO_WAIS)
	return 0;
    if (method == METHOD_CONNECT)
	return 0;
    if (method == METHOD_TRACE)
	return 0;
    if (method == METHOD_PUT)
	return 0;
    if (method == METHOD_POST)
	return 0;		/* XXX POST may be cached sometimes.. ignored for now */
    if (req->protocol == PROTO_GOPHER)
	return gopherCachable(req);
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
	return gopherCachable(request);
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
	if (NULL == http->entry)
	    (void) 0;
	else if (http->entry->timestamp < 0)
	    (void) 0;
	else if (http->entry->timestamp < squid_curtime)
	    httpHeaderPutInt(hdr, HDR_AGE,
		squid_curtime - http->entry->timestamp);
    }
    /* Handle authentication headers */
    if (request->auth_user_request)
	authenticateFixHeader(rep, request->auth_user_request, request, http->flags.accel, 0);
    /* Append X-Cache */
    httpHeaderPutStrf(hdr, HDR_X_CACHE, "%s from %s",
	is_hit ? "HIT" : "MISS", getMyHostname());
#if USE_CACHE_DIGESTS
    /* Append X-Cache-Lookup: -- temporary hack, to be removed @?@ @?@ */
    httpHeaderPutStrf(hdr, HDR_X_CACHE_LOOKUP, "%s from %s:%d",
	http->lookup_type ? http->lookup_type : "NONE",
	getMyHostname(), getMyPort());
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
    httpHdrMangleList(hdr, request);
}

static HttpReply *
clientBuildReply(clientHttpRequest * http, const char *buf, size_t size)
{
    HttpReply *rep = httpReplyCreate();
    size_t k = headersEnd(buf, size);
    if (k && httpReplyParse(rep, buf, k)) {
	/* enforce 1.0 reply version */
	httpBuildVersion(&rep->sline.version, 1, 0);
	/* do header conversions */
	clientBuildReplyHeader(http, rep);
    } else {
	/* parsing failure, get rid of the invalid reply */
	httpReplyDestroy(rep);
	rep = NULL;
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
	debug(33, 3) ("clientCacheHit: request aborted\n");
	return;
    } else if (size < 0) {
	/* swap in failure */
	debug(33, 3) ("clientCacheHit: swapin failure for %s\n", http->uri);
	http->log_type = LOG_TCP_SWAPFAIL_MISS;
	if ((e = http->entry)) {
	    http->entry = NULL;
	    storeUnregister(http->sc, e, http);
	    http->sc = NULL;
	    storeUnlockObject(e);
	}
	clientProcessMiss(http);
	return;
    }
    assert(size > 0);
    mem = e->mem_obj;
    assert(!EBIT_TEST(e->flags, ENTRY_ABORTED));
    /* update size of the request */
    http->reqsize = size + http->reqofs;
    if (mem->reply->sline.status == 0) {
	/*
	 * we don't have full reply headers yet; either wait for more or
	 * punt to clientProcessMiss.
	 */
	if (e->mem_status == IN_MEMORY || e->store_status == STORE_OK) {
	    clientProcessMiss(http);
	} else if (size + http->reqofs >= HTTP_REQBUF_SZ && http->out.offset == 0) {
	    clientProcessMiss(http);
	} else {
	    debug(33, 3) ("clientCacheHit: waiting for HTTP reply headers\n");
	    http->reqofs += size;
	    assert(http->reqofs <= HTTP_REQBUF_SZ);
	    storeClientCopy(http->sc, e,
		http->out.offset + http->reqofs,
		HTTP_REQBUF_SZ,
		http->reqbuf + http->reqofs,
		clientCacheHit,
		http);
	}
	return;
    }
    /*
     * Got the headers, now grok them
     */
    assert(http->log_type == LOG_TCP_HIT);
    switch (varyEvaluateMatch(e, r)) {
    case VARY_NONE:
	/* No variance detected. Continue as normal */
	break;
    case VARY_MATCH:
	/* This is the correct entity for this request. Continue */
	debug(33, 2) ("clientProcessHit: Vary MATCH!\n");
	break;
    case VARY_OTHER:
	/* This is not the correct entity for this request. We need
	 * to requery the cache.
	 */
	http->entry = NULL;
	storeUnregister(http->sc, e, http);
	http->sc = NULL;
	storeUnlockObject(e);
	/* Note: varyEvalyateMatch updates the request with vary information
	 * so we only get here once. (it also takes care of cancelling loops)
	 */
	debug(33, 2) ("clientProcessHit: Vary detected!\n");
	clientProcessRequest(http);
	return;
    case VARY_CANCEL:
	/* varyEvaluateMatch found a object loop. Process as miss */
	debug(33, 1) ("clientProcessHit: Vary object loop!\n");
	clientProcessMiss(http);
	return;
    }
    if (r->method == METHOD_PURGE) {
	http->entry = NULL;
	storeUnregister(http->sc, e, http);
	http->sc = NULL;
	storeUnlockObject(e);
	clientPurgeRequest(http);
	return;
    }
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
    } else if (r->flags.ims) {
	/*
	 * Handle If-Modified-Since requests from the client
	 */
	if (mem->reply->sline.status != HTTP_OK) {
	    debug(33, 4) ("clientCacheHit: Reply code %d != 200\n",
		mem->reply->sline.status);
	    http->log_type = LOG_TCP_MISS;
	    clientProcessMiss(http);
	} else if (modifiedSince(e, http->request)) {
	    http->log_type = LOG_TCP_IMS_HIT;
	    clientSendMoreData(data, buf, size);
	} else {
	    time_t timestamp = e->timestamp;
	    MemBuf mb = httpPacked304Reply(e->mem_obj->reply);
	    http->log_type = LOG_TCP_IMS_HIT;
	    storeUnregister(http->sc, e, http);
	    http->sc = NULL;
	    storeUnlockObject(e);
	    e = clientCreateStoreEntry(http, http->request->method, null_request_flags);
	    /*
	     * Copy timestamp from the original entry so the 304
	     * reply has a meaningful Age: header.
	     */
	    e->timestamp = timestamp;
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


static int
clientReplyBodyTooLarge(HttpReply * rep, ssize_t clen)
{
    if (0 == rep->maxBodySize)
	return 0;		/* disabled */
    if (clen < 0)
	return 0;		/* unknown */
    if (clen > rep->maxBodySize)
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


/* Responses with no body will not have a content-type header, 
 * which breaks the rep_mime_type acl, which
 * coincidentally, is the most common acl for reply access lists.
 * A better long term fix for this is to allow acl matchs on the various
 * status codes, and then supply a default ruleset that puts these 
 * codes before any user defines access entries. That way the user 
 * can choose to block these responses where appropriate, but won't get
 * mysterious breakages.
 */
static int
clientAlwaysAllowResponse(http_status sline)
{
    switch (sline) {
    case HTTP_CONTINUE:
    case HTTP_SWITCHING_PROTOCOLS:
    case HTTP_PROCESSING:
    case HTTP_NO_CONTENT:
    case HTTP_NOT_MODIFIED:
	return 1;
	/* unreached */
	break;
    default:
	return 0;
    }
}


/*
 * accepts chunk of a http message in buf, parses prefix, filters headers and
 * such, writes processed message to the client's socket
 */
static void
clientSendMoreData(void *data, char *retbuf, ssize_t retsize)
{
    clientHttpRequest *http = data;
    StoreEntry *entry = http->entry;
    ConnStateData *conn = http->conn;
    int fd = conn->fd;
    HttpReply *rep = NULL;
    char *buf = http->reqbuf;
    const char *body_buf = buf;
    ssize_t size = http->reqofs + retsize;
    ssize_t body_size = size;
    MemBuf mb;
    ssize_t check_size = 0;

    debug(33, 5) ("clientSendMoreData: %s, %d bytes (%d new bytes)\n", http->uri, (int) size, retsize);
    assert(size <= HTTP_REQBUF_SZ);
    assert(http->request != NULL);
    dlinkDelete(&http->active, &ClientActiveRequests);
    dlinkAdd(http, &http->active, &ClientActiveRequests);
    debug(33, 5) ("clientSendMoreData: FD %d '%s', out.offset=%ld \n",
	fd, storeUrl(entry), (long int) http->out.offset);
    /* update size of the request */
    http->reqsize = size;
    if (conn->chr != http) {
	/* there is another object in progress, defer this one */
	debug(33, 2) ("clientSendMoreData: Deferring %s\n", storeUrl(entry));
	return;
    } else if (http->request->flags.reset_tcp) {
	comm_reset_close(fd);
	return;
    } else if (entry && EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	return;
    } else if (retsize < 0) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
	return;
    } else if (retsize == 0) {
	/* call clientWriteComplete so the client socket gets closed */
	clientWriteComplete(fd, NULL, 0, COMM_OK, http);
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
	    aclCheck_t *ch;
	    int rv;
	    httpReplyBodyBuildSize(http->request, rep, &Config.ReplyBodySize);
	    if (clientReplyBodyTooLarge(rep, rep->content_length)) {
		ErrorState *err = errorCon(ERR_TOO_BIG, HTTP_FORBIDDEN);
		err->request = requestLink(http->request);
		storeUnregister(http->sc, http->entry, http);
		http->sc = NULL;
		storeUnlockObject(http->entry);
		http->entry = clientCreateStoreEntry(http, http->request->method,
		    null_request_flags);
		errorAppendEntry(http->entry, err);
		httpReplyDestroy(rep);
		return;
	    }
	    body_size = size - rep->hdr_sz;
	    assert(body_size >= 0);
	    body_buf = buf + rep->hdr_sz;
	    debug(33, 3) ("clientSendMoreData: Appending %d bytes after %d bytes of headers\n",
		(int) body_size, rep->hdr_sz);
	    ch = aclChecklistCreate(Config.accessList.reply, http->request, NULL);
	    ch->reply = rep;
	    rv = aclCheckFast(Config.accessList.reply, ch);
	    aclChecklistFree(ch);
	    ch = NULL;
	    debug(33, 2) ("The reply for %s %s is %s, because it matched '%s'\n",
		RequestMethodStr[http->request->method], http->uri,
		rv ? "ALLOWED" : "DENIED",
		AclMatchedName ? AclMatchedName : "NO ACL's");
	    if (!rv && rep->sline.status != HTTP_FORBIDDEN
		&& !clientAlwaysAllowResponse(rep->sline.status)) {
		/* the if above is slightly broken, but there is no way
		 * to tell if this is a squid generated error page, or one from
		 * upstream at this point. */
		ErrorState *err;
		err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
		err->request = requestLink(http->request);
		storeUnregister(http->sc, http->entry, http);
		http->sc = NULL;
		storeUnlockObject(http->entry);
		http->entry = clientCreateStoreEntry(http, http->request->method,
		    null_request_flags);
		errorAppendEntry(http->entry, err);
		httpReplyDestroy(rep);
		return;
	    }
	} else if (size < HTTP_REQBUF_SZ && entry->store_status == STORE_PENDING) {
	    /* wait for more to arrive */
	    http->reqofs += retsize;
	    assert(http->reqofs <= HTTP_REQBUF_SZ);
	    storeClientCopy(http->sc, entry,
		http->out.offset + http->reqofs,
		HTTP_REQBUF_SZ - http->reqofs,
		http->reqbuf + http->reqofs,
		clientSendMoreData,
		http);
	    return;
	}
    } else {
	/* Avoid copying to MemBuf if we know "rep" is NULL, and we only have a body */
	http->out.offset += body_size;
	assert(rep == NULL);
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
    if (body_buf && body_size) {
	http->out.offset += body_size;
	check_size += body_size;
	memBufAppend(&mb, body_buf, body_size);
    }
    /* write */
    comm_write_mbuf(fd, mb, clientWriteComplete, http);
    /* if we don't do it, who will? */
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
	fd_note(conn->fd, "Waiting for next request");
	/*
	 * Set the timeout BEFORE calling clientReadRequest().
	 */
	commSetTimeout(conn->fd, Config.Timeout.persistent_request, requestTimeout, conn);
	/*
	 * CYGWIN has a problem and is blocking on read() requests when there
	 * is no data present.
	 * This hack may hit performance a little, but it's better than 
	 * blocking!.
	 */
#ifdef _SQUID_CYGWIN_
	commSetSelect(conn->fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
#else
	clientReadRequest(conn->fd, conn);	/* Read next request */
#endif
	/*
	 * Note, the FD may be closed at this point.
	 */
    } else if ((entry = http->entry) == NULL) {
	/*
	 * this request is in progress, maybe doing an ACL or a redirect,
	 * execution will resume after the operation completes.
	 */
    } else {
	debug(33, 2) ("clientKeepaliveNextRequest: FD %d Sending next\n",
	    conn->fd);
	assert(entry);
	if (0 == storeClientCopyPending(http->sc, entry, http)) {
	    if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
		debug(33, 0) ("clientKeepaliveNextRequest: ENTRY_ABORTED\n");
	    /* If we have any data in our reqbuf, use it */
	    if (http->reqsize > 0) {
		/*
		 * We can pass in reqbuf/size here, since clientSendMoreData ignores what
		 * is passed and uses them itself.. :-)
		 * -- adrian
		 */
		clientSendMoreData(http, http->reqbuf, http->reqsize);
	    } else {
		assert(http->out.offset == 0);
		/*
		 * here - have no data (don't ever think we get here..)
		 * so lets start copying..
		 * -- adrian
		 */
		storeClientCopy(http->sc, entry,
		    http->out.offset,
		    HTTP_REQBUF_SZ,
		    http->reqbuf,
		    clientSendMoreData,
		    http);
	    }
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
    debug(33, 5) ("clientWriteComplete: FD %d, sz %ld, err %d, off %ld, len %d\n",
	fd, (long int) size, errflag, (long int) http->out.offset, entry ? objectLen(entry) : 0);
    if (size > 0) {
	kb_incr(&statCounter.client_http.kbytes_out, size);
	if (isTcpHit(http->log_type))
	    kb_incr(&statCounter.client_http.hit_kbytes_out, size);
    }
#if SIZEOF_SIZE_T == 4
    if (http->out.size > 0x7FFF0000) {
	debug(33, 1) ("WARNING: closing FD %d to prevent counter overflow\n", fd);
	debug(33, 1) ("\tclient %s\n", inet_ntoa(http->conn->peer.sin_addr));
	debug(33, 1) ("\treceived %d bytes\n", (int) http->out.size);
	debug(33, 1) ("\tURI %s\n", http->log_uri);
	comm_close(fd);
    } else
#endif
#if SIZEOF_OFF_T == 4
    if (http->out.offset > 0x7FFF0000) {
	debug(33, 1) ("WARNING: closing FD %d to prevent counter overflow\n", fd);
	debug(33, 1) ("\tclient %s\n", inet_ntoa(http->conn->peer.sin_addr));
	debug(33, 1) ("\treceived %d bytes (offset %d)\n", (int) http->out.size,
	    (int) http->out.offset);
	debug(33, 1) ("\tURI %s\n", http->log_uri);
	comm_close(fd);
    } else
#endif
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
    } else if (clientReplyBodyTooLarge(entry->mem_obj->reply, http->out.offset)) {
	comm_close(fd);
    } else {
	/* More data will be coming from primary server; register with 
	 * storage manager. */
	if (EBIT_TEST(entry->flags, ENTRY_ABORTED))
	    debug(33, 0) ("clientWriteComplete 2: ENTRY_ABORTED\n");
	http->reqofs = 0;
	storeClientCopy(http->sc, entry,
	    http->out.offset,
	    HTTP_REQBUF_SZ,
	    http->reqbuf,
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
	http->sc = NULL;
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
    if (r->flags.cachable || r->flags.internal)
	e = http->entry = storeGetPublicByRequest(r);
    else
	e = http->entry = NULL;
    /* Release negatively cached IP-cache entries on reload */
    if (r->flags.nocache)
	ipcacheInvalidate(r->host);
#if HTTP_VIOLATIONS
    else if (r->flags.nocache_hack)
	ipcacheInvalidate(r->host);
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
    if (http->redirect.status) {
	/* force this to be a miss */
	http->entry = NULL;
	return LOG_TCP_MISS;
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
	return LOG_TCP_CLIENT_REFRESH_MISS;
    }
    /* We don't cache any range requests (for now!) -- adrian */
    if (r->flags.range) {
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
    HttpReply *rep;
    http_version_t version;
    debug(33, 4) ("clientProcessRequest: %s '%s'\n",
	RequestMethodStr[r->method],
	url);
    if (r->method == METHOD_CONNECT) {
	http->log_type = LOG_TCP_MISS;
	sslStart(http, &http->out.size, &http->al.http.code);
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
	    httpBuildVersion(&version, 1, 0);
	    httpReplySetHeaders(rep, version, HTTP_OK, NULL, "text/plain",
		httpRequestPrefixLen(r), 0, squid_curtime);
	    httpReplySwapOut(rep, http->entry);
	    httpReplyDestroy(rep);
	    httpRequestSwapOut(r, http->entry);
	    storeComplete(http->entry);
	    return;
	}
	/* yes, continue */
	http->log_type = LOG_TCP_MISS;
    } else {
	http->log_type = clientProcessRequest2(http);
    }
    debug(33, 4) ("clientProcessRequest: %s for '%s'\n",
	log_tags[http->log_type],
	http->uri);
    http->out.offset = 0;
    if (NULL != http->entry) {
	storeLockObject(http->entry);
	if (NULL == http->entry->mem_obj) {
	    /*
	     * This if-block exists because we don't want to clobber
	     * a preexiting mem_obj->method value if the mem_obj
	     * already exists.  For example, when a HEAD request
	     * is a cache hit for a GET response, we want to keep
	     * the method as GET.
	     */
	    storeCreateMemObject(http->entry, http->uri, http->log_uri);
	    http->entry->mem_obj->method = r->method;
	}
	http->sc = storeClientListAdd(http->entry, http);
#if DELAY_POOLS
	delaySetStoreClient(http->sc, delayClient(http));
#endif
	assert(http->log_type == LOG_TCP_HIT);
	http->reqofs = 0;
	storeClientCopy(http->sc, http->entry,
	    http->out.offset,
	    HTTP_REQBUF_SZ,
	    http->reqbuf,
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
	if (EBIT_TEST(http->entry->flags, ENTRY_SPECIAL)) {
	    debug(33, 0) ("clientProcessMiss: miss on a special object (%s).\n", url);
	    debug(33, 0) ("\tlog_type = %s\n", log_tags[http->log_type]);
	    storeEntryDump(http->entry, 1);
	}
	storeUnregister(http->sc, http->entry, http);
	http->sc = NULL;
	storeUnlockObject(http->entry);
	http->entry = NULL;
    }
    if (r->method == METHOD_PURGE) {
	clientPurgeRequest(http);
	return;
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
    clientHttpRequest *http;
    http = cbdataAlloc(clientHttpRequest);
    http->conn = conn;
    http->start = current_time;
    http->req_sz = conn->in.offset;
    http->uri = xstrdup(uri);
    http->log_uri = xstrndup(uri, MAX_URL);
    http->reqbuf = http->norm_reqbuf;
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
    http_version_t http_ver;
    char *token = NULL;
    char *t = NULL;
    char *end;
    size_t header_sz;		/* size of headers, not including first line */
    size_t prefix_sz;		/* size of whole request (req-line + headers) */
    size_t url_sz;
    size_t req_sz;
    method_t method;
    clientHttpRequest *http = NULL;
#if IPF_TRANSPARENT
    struct natlookup natLookup;
    static int natfd = -1;
    static int siocgnatl_cmd = SIOCGNATL & 0xff;
    int x;
#endif
#if PF_TRANSPARENT
    struct pfioc_natlook nl;
    static int pffd = -1;
#endif
#if LINUX_NETFILTER
    size_t sock_sz = sizeof(conn->me);
#endif

    /* pre-set these values to make aborting simpler */
    *prefix_p = NULL;
    *method_p = METHOD_NONE;
    *status = -1;

    if ((req_sz = headersEnd(conn->in.buf, conn->in.offset)) == 0) {
	debug(33, 5) ("Incomplete request, waiting for end of headers\n");
	*status = 0;
	return NULL;
    }
    assert(req_sz <= conn->in.offset);
    /* Use memcpy, not strdup! */
    inbuf = xmalloc(req_sz + 1);
    xmemcpy(inbuf, conn->in.buf, req_sz);
    *(inbuf + req_sz) = '\0';

    /* Barf on NULL characters in the headers */
    if (strlen(inbuf) != req_sz) {
	debug(33, 1) ("parseHttpRequest: Requestheader contains NULL characters\n");
	xfree(inbuf);
	return parseHttpRequestAbort(conn, "error:invalid-request");
    }
    /* Look for request method */
    if ((mstr = strtok(inbuf, "\t ")) == NULL) {
	debug(33, 1) ("parseHttpRequest: Can't get request method\n");
	xfree(inbuf);
	return parseHttpRequestAbort(conn, "error:invalid-request-method");
    }
    method = urlParseMethod(mstr);
    if (method == METHOD_NONE) {
	debug(33, 1) ("parseHttpRequest: Unsupported method '%s'\n", mstr);
	xfree(inbuf);
	return parseHttpRequestAbort(conn, "error:unsupported-request-method");
    }
    debug(33, 5) ("parseHttpRequest: Method is '%s'\n", mstr);
    *method_p = method;

    /* look for URL+HTTP/x.x */
    if ((url = strtok(NULL, "\n")) == NULL) {
	debug(33, 1) ("parseHttpRequest: Missing URL\n");
	xfree(inbuf);
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
	httpBuildVersion(&http_ver, 0, 9);	/* wild guess */
#else
	xfree(inbuf);
	return parseHttpRequestAbort(conn, "error:missing-http-ident");
#endif
    } else {
	if (sscanf(token + 5, "%d.%d", &http_ver.major, &http_ver.minor) != 2) {
	    debug(33, 3) ("parseHttpRequest: Invalid HTTP identifier.\n");
	    xfree(inbuf);
	    return parseHttpRequestAbort(conn, "error: invalid HTTP-ident");
	}
	debug(33, 6) ("parseHttpRequest: Client HTTP version %d.%d.\n", http_ver.major, http_ver.minor);
    }

    /*
     * Process headers after request line
     */
    req_hdr = strtok(NULL, null_string);
    header_sz = req_sz - (req_hdr - inbuf);
    if (0 == header_sz) {
	debug(33, 3) ("parseHttpRequest: header_sz == 0\n");
	*status = 0;
	xfree(inbuf);
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
    http = cbdataAlloc(clientHttpRequest);
    http->http_ver = http_ver;
    http->conn = conn;
    http->start = current_time;
    http->req_sz = prefix_sz;
    http->reqbuf = http->norm_reqbuf;
    *prefix_p = xmalloc(prefix_sz + 1);
    xmemcpy(*prefix_p, conn->in.buf, prefix_sz);
    *(*prefix_p + prefix_sz) = '\0';
    dlinkAdd(http, &http->active, &ClientActiveRequests);

    debug(33, 5) ("parseHttpRequest: Request Header is\n%s\n", (*prefix_p) + *req_line_sz_p);
#if THIS_VIOLATES_HTTP_SPECS_ON_URL_TRANSFORMATION
    if ((t = strchr(url, '#')))	/* remove HTML anchors */
	*t = '\0';
#endif

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
	    int vport;
	    char *q;
	    const char *protocol_name = "http";
	    if (vport_mode)
		vport = (int) ntohs(http->conn->me.sin_port);
	    else
		vport = (int) Config.Accel.port;
	    /* If a Host: header was specified, use it to build the URL 
	     * instead of the one in the Config file. */
	    /*
	     * XXX Use of the Host: header here opens a potential
	     * security hole.  There are no checks that the Host: value
	     * corresponds to one of your servers.  It might, for example,
	     * refer to www.playboy.com.  The 'dst' and/or 'dst_domain' ACL 
	     * types should be used to prevent httpd-accelerators 
	     * handling requests for non-local servers */
	    strtok(t, " /;@");
	    if ((q = strchr(t, ':'))) {
		*q++ = '\0';
		if (vport_mode)
		    vport = atoi(q);
	    }
	    url_sz = strlen(url) + 32 + Config.appendDomainLen +
		strlen(t);
	    http->uri = xcalloc(url_sz, 1);

#if SSL_FORWARDING_NOT_YET_DONE
	    if (Config.Sockaddr.https->s.sin_port == http->conn->me.sin_port) {
		protocol_name = "https";
		vport = ntohs(http->conn->me.sin_port);
	    }
#endif
	    snprintf(http->uri, url_sz, "%s://%s:%d%s",
		protocol_name, t, vport, url);
	} else if (vhost_mode) {
	    int vport;
	    /* Put the local socket IP address as the hostname */
	    url_sz = strlen(url) + 32 + Config.appendDomainLen;
	    http->uri = xcalloc(url_sz, 1);
	    if (vport_mode)
		vport = (int) ntohs(http->conn->me.sin_port);
	    else
		vport = (int) Config.Accel.port;
#if IPF_TRANSPARENT
	    natLookup.nl_inport = http->conn->me.sin_port;
	    natLookup.nl_outport = http->conn->peer.sin_port;
	    natLookup.nl_inip = http->conn->me.sin_addr;
	    natLookup.nl_outip = http->conn->peer.sin_addr;
	    natLookup.nl_flags = IPN_TCP;
	    if (natfd < 0) {
		int save_errno;
		enter_suid();
		natfd = open(IPL_NAT, O_RDONLY, 0);
		save_errno = errno;
		leave_suid();
		errno = save_errno;
	    }
	    if (natfd < 0) {
		debug(50, 1) ("parseHttpRequest: NAT open failed: %s\n",
		    xstrerror());
		dlinkDelete(&http->active, &ClientActiveRequests);
		xfree(http->uri);
		cbdataFree(http);
		xfree(inbuf);
		return parseHttpRequestAbort(conn, "error:nat-open-failed");
	    }
	    /*
	     * IP-Filter changed the type for SIOCGNATL between
	     * 3.3 and 3.4.  It also changed the cmd value for
	     * SIOCGNATL, so at least we can detect it.  We could
	     * put something in configure and use ifdefs here, but
	     * this seems simpler.
	     */
	    if (63 == siocgnatl_cmd) {
		struct natlookup *nlp = &natLookup;
		x = ioctl(natfd, SIOCGNATL, &nlp);
	    } else {
		x = ioctl(natfd, SIOCGNATL, &natLookup);
	    }
	    if (x < 0) {
		if (errno != ESRCH) {
		    debug(50, 1) ("parseHttpRequest: NAT lookup failed: ioctl(SIOCGNATL)\n");
		    close(natfd);
		    natfd = -1;
		    dlinkDelete(&http->active, &ClientActiveRequests);
		    xfree(http->uri);
		    cbdataFree(http);
		    xfree(inbuf);
		    return parseHttpRequestAbort(conn, "error:nat-lookup-failed");
		} else
		    snprintf(http->uri, url_sz, "http://%s:%d%s",
			inet_ntoa(http->conn->me.sin_addr),
			vport, url);
	    } else {
		if (vport_mode)
		    vport = ntohs(natLookup.nl_realport);
		snprintf(http->uri, url_sz, "http://%s:%d%s",
		    inet_ntoa(natLookup.nl_realip),
		    vport, url);
	    }
#elif PF_TRANSPARENT
	    if (pffd < 0)
		pffd = open("/dev/pf", O_RDWR);
	    if (pffd < 0) {
		debug(50, 1) ("parseHttpRequest: PF open failed: %s\n",
		    xstrerror());
		return parseHttpRequestAbort(conn, "error:pf-open-failed");
	    }
	    memset(&nl, 0, sizeof(struct pfioc_natlook));
	    nl.saddr.v4.s_addr = http->conn->peer.sin_addr.s_addr;
	    nl.sport = http->conn->peer.sin_port;
	    nl.daddr.v4.s_addr = http->conn->me.sin_addr.s_addr;
	    nl.dport = http->conn->me.sin_port;
	    nl.af = AF_INET;
	    nl.proto = IPPROTO_TCP;
	    nl.direction = PF_OUT;
	    if (ioctl(pffd, DIOCNATLOOK, &nl)) {
		if (errno != ENOENT) {
		    debug(50, 1) ("parseHttpRequest: PF lookup failed: ioctl(DIOCNATLOOK)\n");
		    close(pffd);
		    pffd = -1;
		    return parseHttpRequestAbort(conn, "error:pf-lookup-failed");
		} else
		    snprintf(http->uri, url_sz, "http://%s:%d%s",
			inet_ntoa(http->conn->me.sin_addr),
			vport, url);
	    } else
		snprintf(http->uri, url_sz, "http://%s:%d%s",
		    inet_ntoa(nl.rdaddr.v4),
		    ntohs(nl.rdport), url);
#else
#if LINUX_NETFILTER
	    /* If the call fails the address structure will be unchanged */
	    getsockopt(conn->fd, SOL_IP, SO_ORIGINAL_DST, &conn->me, &sock_sz);
	    debug(33, 5) ("parseHttpRequest: addr = %s", inet_ntoa(conn->me.sin_addr));
	    if (vport_mode)
		vport = (int) ntohs(http->conn->me.sin_port);
#endif
	    snprintf(http->uri, url_sz, "http://%s:%d%s",
		inet_ntoa(http->conn->me.sin_addr),
		vport, url);
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
    xfree(inbuf);
    *status = 1;
    return http;
}

static int
clientReadDefer(int fdnotused, void *data)
{
    ConnStateData *conn = data;
    if (conn->body.size_left)
	return conn->in.offset >= conn->in.size - 1;
    else
	return conn->defer.until > squid_curtime;
}

static void
clientReadRequest(int fd, void *data)
{
    ConnStateData *conn = data;
    int parser_return_code = 0;
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
    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
    if (len == 0) {
	/* Grow the request memory area to accomodate for a large request */
	conn->in.buf = memReallocBuf(conn->in.buf, conn->in.size * 2, &conn->in.size);
	debug(33, 2) ("growing request buffer: offset=%ld size=%ld\n",
	    (long) conn->in.offset, (long) conn->in.size);
	len = conn->in.size - conn->in.offset - 1;
    }
    statCounter.syscalls.sock.reads++;
    size = FD_READ_METHOD(fd, conn->in.buf + conn->in.offset, len);
    if (size > 0) {
	fd_bytes(fd, size, FD_READ);
	kb_incr(&statCounter.client_http.kbytes_in, size);
    }
    /*
     * Don't reset the timeout value here.  The timeout value will be
     * set to Config.Timeout.request by httpAccept() and
     * clientWriteComplete(), and should apply to the request as a
     * whole, not individual read() calls.  Plus, it breaks our
     * lame half-close detection
     */
    if (size > 0) {
	conn->in.offset += size;
	conn->in.buf[conn->in.offset] = '\0';	/* Terminate the string */
    } else if (size == 0) {
	if (conn->chr == NULL && conn->in.offset == 0) {
	    /* no current or pending requests */
	    debug(33, 4) ("clientReadRequest: FD %d closed\n", fd);
	    comm_close(fd);
	    return;
	} else if (!Config.onoff.half_closed_clients) {
	    /* admin doesn't want to support half-closed client sockets */
	    debug(33, 3) ("clientReadRequest: FD %d aborted (half_closed_clients disabled)\n", fd);
	    comm_close(fd);
	    return;
	}
	/* It might be half-closed, we can't tell */
	debug(33, 5) ("clientReadRequest: FD %d closed?\n", fd);
	F->flags.socket_eof = 1;
	conn->defer.until = squid_curtime + 1;
	conn->defer.n++;
	fd_note(fd, "half-closed");
	/* There is one more close check at the end, to detect aborted
	 * (partial) requests. At this point we can't tell if the request
	 * is partial.
	 */
	/* Continue to process previously read data */
    } else if (size < 0) {
	if (!ignoreErrno(errno)) {
	    debug(50, 2) ("clientReadRequest: FD %d: %s\n", fd, xstrerror());
	    comm_close(fd);
	    return;
	} else if (conn->in.offset == 0) {
	    debug(50, 2) ("clientReadRequest: FD %d: no data to process (%s)\n", fd, xstrerror());
	}
	/* Continue to process previously read data */
    }
    /* Process request body if any */
    if (conn->in.offset > 0 && conn->body.callback != NULL)
	clientProcessBody(conn);
    /* Process next request */
    while (conn->in.offset > 0 && conn->body.size_left == 0) {
	int nrequests;
	size_t req_line_sz;
	/* Skip leading (and trailing) whitespace */
	while (conn->in.offset > 0 && xisspace(conn->in.buf[0])) {
	    xmemmove(conn->in.buf, conn->in.buf + 1, conn->in.offset - 1);
	    conn->in.offset--;
	}
	conn->in.buf[conn->in.offset] = '\0';	/* Terminate the string */
	if (conn->in.offset == 0)
	    break;
	/* Limit the number of concurrent requests to 2 */
	for (H = &conn->chr, nrequests = 0; *H; H = &(*H)->next, nrequests++);
	if (nrequests >= (Config.onoff.pipeline_prefetch ? 2 : 1)) {
	    debug(33, 3) ("clientReadRequest: FD %d max concurrent requests reached\n", fd);
	    debug(33, 5) ("clientReadRequest: FD %d defering new request until one is done\n", fd);
	    conn->defer.until = squid_curtime + 100;	/* Reset when a request is complete */
	    conn->defer.n++;
	    return;
	}
	conn->in.buf[conn->in.offset] = '\0';	/* Terminate the string */
	if (nrequests == 0)
	    fd_note(conn->fd, "Reading next request");
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
	    commSetTimeout(fd, Config.Timeout.lifetime, clientLifetimeTimeout, http);
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
			request->port == getMyPort()) {
			http->flags.internal = 1;
		    } else if (internalStaticCheck(strBuf(request->urlpath))) {
			xstrncpy(request->host, internalHostname(), SQUIDHOSTNAMELEN);
			request->port = getMyPort();
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
	    if (!urlCheckRequest(request) ||
		httpHeaderHas(&request->header, HDR_TRANSFER_ENCODING)) {
		err = errorCon(ERR_UNSUP_REQ, HTTP_NOT_IMPLEMENTED);
		err->src_addr = conn->peer.sin_addr;
		err->request = requestLink(request);
		request->flags.proxy_keepalive = 0;
		http->al.http.code = err->http_status;
		http->entry = clientCreateStoreEntry(http, request->method, null_request_flags);
		errorAppendEntry(http->entry, err);
		break;
	    }
	    if (!clientCheckContentLength(request)) {
		err = errorCon(ERR_INVALID_REQ, HTTP_LENGTH_REQUIRED);
		err->src_addr = conn->peer.sin_addr;
		err->request = requestLink(request);
		http->al.http.code = err->http_status;
		http->entry = clientCreateStoreEntry(http, request->method, null_request_flags);
		errorAppendEntry(http->entry, err);
		break;
	    }
	    http->request = requestLink(request);
	    clientSetKeepaliveFlag(http);
	    /* Do we expect a request-body? */
	    if (request->content_length > 0) {
		conn->body.size_left = request->content_length;
		request->body_connection = conn;
		/* Is it too large? */
		if (clientRequestBodyTooLarge(request->content_length)) {
		    err = errorCon(ERR_TOO_BIG, HTTP_REQUEST_ENTITY_TOO_LARGE);
		    err->request = requestLink(request);
		    http->entry = clientCreateStoreEntry(http,
			METHOD_NONE, null_request_flags);
		    errorAppendEntry(http->entry, err);
		    break;
		}
	    }
	    clientAccessCheck(http);
	    continue;		/* while offset > 0 && body.size_left == 0 */
	} else if (parser_return_code == 0) {
	    /*
	     *    Partial request received; reschedule until parseHttpRequest()
	     *    is happy with the input
	     */
	    if (conn->in.offset >= Config.maxRequestHeaderSize) {
		/* The request is too large to handle */
		debug(33, 1) ("Request header is too large (%d bytes)\n",
		    (int) conn->in.offset);
		debug(33, 1) ("Config 'request_header_max_size'= %ld bytes.\n",
		    (long int) Config.maxRequestHeaderSize);
		err = errorCon(ERR_TOO_BIG, HTTP_REQUEST_ENTITY_TOO_LARGE);
		http = parseHttpRequestAbort(conn, "error:request-too-large");
		/* add to the client request queue */
		for (H = &conn->chr; *H; H = &(*H)->next);
		*H = http;
		http->entry = clientCreateStoreEntry(http, METHOD_NONE, null_request_flags);
		errorAppendEntry(http->entry, err);
		return;
	    }
	    break;
	}
    }				/* while offset > 0 && conn->body.size_left == 0 */
    /* Check if a half-closed connection was aborted in the middle */
    if (F->flags.socket_eof) {
	if (conn->in.offset != conn->body.size_left) {	/* != 0 when no request body */
	    /* Partial request received. Abort client connection! */
	    debug(33, 3) ("clientReadRequest: FD %d aborted, partial request\n", fd);
	    comm_close(fd);
	    return;
	}
    }
}

/* file_read like function, for reading body content */
void
clientReadBody(request_t * request, char *buf, size_t size, CBCB * callback, void *cbdata)
{
    ConnStateData *conn = request->body_connection;
    if (!conn) {
	debug(33, 5) ("clientReadBody: no body to read, request=%p\n", request);
	callback(buf, 0, cbdata);	/* Signal end of body */
	return;
    }
    debug(33, 2) ("clientReadBody: start fd=%d body_size=%lu in.offset=%ld cb=%p req=%p\n", conn->fd, (unsigned long int) conn->body.size_left, (long int) conn->in.offset, callback, request);
    conn->body.callback = callback;
    conn->body.cbdata = cbdata;
    conn->body.buf = buf;
    conn->body.bufsize = size;
    conn->body.request = requestLink(request);
    clientProcessBody(conn);
}

/* Called by clientReadRequest to process body content */
static void
clientProcessBody(ConnStateData * conn)
{
    int size;
    char *buf = conn->body.buf;
    void *cbdata = conn->body.cbdata;
    CBCB *callback = conn->body.callback;
    request_t *request = conn->body.request;
    /* Note: request is null while eating "aborted" transfers */
    debug(33, 2) ("clientProcessBody: start fd=%d body_size=%lu in.offset=%ld cb=%p req=%p\n", conn->fd, (unsigned long int) conn->body.size_left, (long int) conn->in.offset, callback, request);
    if (conn->in.offset) {
	/* Some sanity checks... */
	assert(conn->body.size_left > 0);
	assert(conn->in.offset > 0);
	assert(callback != NULL);
	assert(buf != NULL);
	/* How much do we have to process? */
	size = conn->in.offset;
	if (size > conn->body.size_left)	/* only process the body part */
	    size = conn->body.size_left;
	if (size > conn->body.bufsize)	/* don't copy more than requested */
	    size = conn->body.bufsize;
	xmemcpy(buf, conn->in.buf, size);
	conn->body.size_left -= size;
	/* Move any remaining data */
	conn->in.offset -= size;
	if (conn->in.offset > 0)
	    xmemmove(conn->in.buf, conn->in.buf + size, conn->in.offset);
	/* Remove request link if this is the last part of the body, as
	 * clientReadRequest automatically continues to process next request */
	if (conn->body.size_left <= 0 && request != NULL)
	    request->body_connection = NULL;
	/* Remove clientReadBody arguments (the call is completed) */
	conn->body.request = NULL;
	conn->body.callback = NULL;
	conn->body.buf = NULL;
	conn->body.bufsize = 0;
	/* Remember that we have touched the body, not restartable */
	if (request != NULL)
	    request->flags.body_sent = 1;
	/* Invoke callback function */
	callback(buf, size, cbdata);
	if (request != NULL)
	    requestUnlink(request);	/* Linked in clientReadBody */
	debug(33, 2) ("clientProcessBody: end fd=%d size=%d body_size=%lu in.offset=%ld cb=%p req=%p\n", conn->fd, size, (unsigned long int) conn->body.size_left, (long int) conn->in.offset, callback, request);
    }
}

/* A dummy handler that throws away a request-body */
static char bodyAbortBuf[SQUID_TCP_SO_RCVBUF];
static void
clientReadBodyAbortHandler(char *buf, size_t size, void *data)
{
    ConnStateData *conn = (ConnStateData *) data;
    debug(33, 2) ("clientReadBodyAbortHandler: fd=%d body_size=%lu in.offset=%ld\n", conn->fd, (unsigned long int) conn->body.size_left, (long int) conn->in.offset);
    if (size != 0 && conn->body.size_left != 0) {
	debug(33, 3) ("clientReadBodyAbortHandler: fd=%d shedule next read\n", conn->fd);
	conn->body.callback = clientReadBodyAbortHandler;
	conn->body.buf = bodyAbortBuf;
	conn->body.bufsize = sizeof(bodyAbortBuf);
	conn->body.cbdata = data;
    }
}

/* Abort a body request */
int
clientAbortBody(request_t * request)
{
    ConnStateData *conn = request->body_connection;
    char *buf;
    CBCB *callback;
    void *cbdata;
    request->body_connection = NULL;
    if (!conn || conn->body.size_left <= 0)
	return 0;		/* No body to abort */
    if (conn->body.callback != NULL) {
	buf = conn->body.buf;
	callback = conn->body.callback;
	cbdata = conn->body.cbdata;
	assert(request == conn->body.request);
	conn->body.buf = NULL;
	conn->body.callback = NULL;
	conn->body.cbdata = NULL;
	conn->body.request = NULL;
	callback(buf, -1, cbdata);	/* Signal abort to clientReadBody caller */
	requestUnlink(request);
    }
    clientReadBodyAbortHandler(NULL, -1, conn);		/* Install abort handler */
    /* clientProcessBody() */
    return 1;			/* Aborted */
}

/* general lifetime handler for HTTP requests */
static void
requestTimeout(int fd, void *data)
{
#if THIS_CONFUSES_PERSISTENT_CONNECTION_AWARE_BROWSERS_AND_USERS
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
#else
    /*
     * Just close the connection to not confuse browsers
     * using persistent connections. Some browsers opens
     * an connection and then does not use it until much
     * later (presumeably because the request triggering
     * the open has already been completed on another
     * connection)
     */
    debug(33, 3) ("requestTimeout: FD %d: lifetime is expired.\n", fd);
    comm_close(fd);
#endif
}

static void
clientLifetimeTimeout(int fd, void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn = http->conn;
    debug(33, 1) ("WARNING: Closing client %s connection due to lifetime timeout\n",
	inet_ntoa(conn->peer.sin_addr));
    debug(33, 1) ("\t%s\n", http->uri);
    comm_close(fd);
}

static int
httpAcceptDefer(int fdunused, void *dataunused)
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
    int *N = &incoming_sockets_accepted;
    int fd = -1;
    ConnStateData *connState = NULL;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    int max = INCOMING_HTTP_MAX;
#if USE_IDENT
    static aclCheck_t identChecklist;
#endif
    commSetSelect(sock, COMM_SELECT_READ, httpAccept, NULL, 0);
    while (max-- && !httpAcceptDefer(sock, NULL)) {
	memset(&peer, '\0', sizeof(struct sockaddr_in));
	memset(&me, '\0', sizeof(struct sockaddr_in));
	if ((fd = comm_accept(sock, &peer, &me)) < 0) {
	    if (!ignoreErrno(errno))
		debug(50, 1) ("httpAccept: FD %d: accept failure: %s\n",
		    sock, xstrerror());
	    break;
	}
	debug(33, 4) ("httpAccept: FD %d: accepted\n", fd);
	connState = cbdataAlloc(ConnStateData);
	connState->peer = peer;
	connState->log_addr = peer.sin_addr;
	connState->log_addr.s_addr &= Config.Addrs.client_netmask.s_addr;
	connState->me = me;
	connState->fd = fd;
	connState->in.buf = memAllocBuf(CLIENT_REQ_BUF_SZ, &connState->in.size);
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

#if USE_SSL

/* negotiate an SSL connection */
static void
clientNegotiateSSL(int fd, void *data)
{
    ConnStateData *conn = data;
    X509 *client_cert;
    int ret;

    if ((ret = SSL_accept(fd_table[fd].ssl)) <= 0) {
	if (BIO_sock_should_retry(ret)) {
	    commSetSelect(fd, COMM_SELECT_READ, clientNegotiateSSL, conn, 0);
	    return;
	}
	ret = ERR_get_error();
	if (ret) {
	    debug(83, 1) ("clientNegotiateSSL: Error negotiating SSL connection on FD %d: %s\n",
		fd, ERR_error_string(ret, NULL));
	}
	comm_close(fd);
	return;
    }
    debug(83, 5) ("clientNegotiateSSL: FD %d negotiated cipher %s\n", fd,
	SSL_get_cipher(fd_table[fd].ssl));

    client_cert = SSL_get_peer_certificate(fd_table[fd].ssl);
    if (client_cert != NULL) {
	debug(83, 5) ("clientNegotiateSSL: FD %d client certificate: subject: %s\n", fd,
	    X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0));

	debug(83, 5) ("clientNegotiateSSL: FD %d client certificate: issuer: %s\n", fd,
	    X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0));

	X509_free(client_cert);
    } else {
	debug(83, 5) ("clientNegotiateSSL: FD %d has no certificate.\n", fd);
    }

    commSetSelect(fd, COMM_SELECT_READ, clientReadRequest, conn, 0);
}

struct _https_port_data {
    SSL_CTX *sslContext;
};
typedef struct _https_port_data https_port_data;
CBDATA_TYPE(https_port_data);

/* handle a new HTTPS connection */
static void
httpsAccept(int sock, void *data)
{
    int *N = &incoming_sockets_accepted;
    https_port_data *https_port = data;
    SSL_CTX *sslContext = https_port->sslContext;
    int fd = -1;
    ConnStateData *connState = NULL;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    int max = INCOMING_HTTP_MAX;
    SSL *ssl;
    int ssl_error;
#if USE_IDENT
    static aclCheck_t identChecklist;
#endif
    commSetSelect(sock, COMM_SELECT_READ, httpsAccept, https_port, 0);
    while (max-- && !httpAcceptDefer(sock, NULL)) {
	memset(&peer, '\0', sizeof(struct sockaddr_in));
	memset(&me, '\0', sizeof(struct sockaddr_in));
	if ((fd = comm_accept(sock, &peer, &me)) < 0) {
	    if (!ignoreErrno(errno))
		debug(50, 1) ("httpsAccept: FD %d: accept failure: %s\n",
		    sock, xstrerror());
	    break;
	}
	if ((ssl = SSL_new(sslContext)) == NULL) {
	    ssl_error = ERR_get_error();
	    debug(83, 1) ("httpsAccept: Error allocating handle: %s\n",
		ERR_error_string(ssl_error, NULL));
	    break;
	}
	SSL_set_fd(ssl, fd);
	fd_table[fd].ssl = ssl;
	fd_table[fd].read_method = &ssl_read_method;
	fd_table[fd].write_method = &ssl_write_method;
	debug(50, 5) ("httpsAccept: FD %d accepted, starting SSL negotiation.\n", fd);

	connState = cbdataAlloc(ConnStateData);
	connState->peer = peer;
	connState->log_addr = peer.sin_addr;
	connState->log_addr.s_addr &= Config.Addrs.client_netmask.s_addr;
	connState->me = me;
	connState->fd = fd;
	connState->in.buf = memAllocBuf(CLIENT_REQ_BUF_SZ, &connState->in.size);
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
	commSetSelect(fd, COMM_SELECT_READ, clientNegotiateSSL, connState, 0);
	commSetDefer(fd, clientReadDefer, connState);
	clientdbEstablished(peer.sin_addr, 1);
	(*N)++;
    }
}

#endif /* USE_SSL */

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

static void
clientHttpConnectionsOpen(void)
{
    sockaddr_in_list *s;
    int fd;
    for (s = Config.Sockaddr.http; s; s = s->next) {
	if (MAXHTTPPORTS == NHttpSockets) {
	    debug(1, 1) ("WARNING: You have too many 'http_port' lines.\n");
	    debug(1, 1) ("         The limit is %d\n", MAXHTTPPORTS);
	    continue;
	}
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
	/*
	 * We need to set a defer handler here so that we don't
	 * peg the CPU with select() when we hit the FD limit.
	 */
	commSetDefer(fd, httpAcceptDefer, NULL);
	debug(1, 1) ("Accepting HTTP connections at %s, port %d, FD %d.\n",
	    inet_ntoa(s->s.sin_addr),
	    (int) ntohs(s->s.sin_port),
	    fd);
	HttpSockets[NHttpSockets++] = fd;
    }
}

#if USE_SSL
static void
clientHttpsConnectionsOpen(void)
{
    https_port_list *s;
    https_port_data *https_port;
    int fd;
    for (s = Config.Sockaddr.https; s; s = s->next) {
	if (MAXHTTPPORTS == NHttpSockets) {
	    debug(1, 1) ("WARNING: You have too many 'https_port' lines.\n");
	    debug(1, 1) ("         The limit is %d\n", MAXHTTPPORTS);
	    continue;
	}
	enter_suid();
	fd = comm_open(SOCK_STREAM,
	    0,
	    s->s.sin_addr,
	    ntohs(s->s.sin_port),
	    COMM_NONBLOCKING,
	    "HTTPS Socket");
	leave_suid();
	if (fd < 0)
	    continue;
	CBDATA_INIT_TYPE(https_port_data);
	https_port = cbdataAlloc(https_port_data);
	https_port->sslContext = sslCreateContext(s->cert, s->key, s->version, s->cipher, s->options);
	comm_listen(fd);
	commSetSelect(fd, COMM_SELECT_READ, httpsAccept, https_port, 0);
	commSetDefer(fd, httpAcceptDefer, NULL);
	debug(1, 1) ("Accepting HTTPS connections at %s, port %d, FD %d.\n",
	    inet_ntoa(s->s.sin_addr),
	    (int) ntohs(s->s.sin_port),
	    fd);
	HttpSockets[NHttpSockets++] = fd;
    }
}

#endif

void
clientOpenListenSockets(void)
{
    clientHttpConnectionsOpen();
#if USE_SSL
    clientHttpsConnectionsOpen();
#endif
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

int
varyEvaluateMatch(StoreEntry * entry, request_t * request)
{
    const char *vary = request->vary_headers;
    int has_vary = httpHeaderHas(&entry->mem_obj->reply->header, HDR_VARY);
#if X_ACCELERATOR_VARY
    has_vary |= httpHeaderHas(&entry->mem_obj->reply->header, HDR_X_ACCELERATOR_VARY);
#endif
    if (!has_vary || !entry->mem_obj->vary_headers) {
	if (vary) {
	    /* Oops... something odd is going on here.. */
	    debug(33, 1) ("varyEvaluateMatch: Oops. Not a Vary object on second attempt, '%s' '%s'\n",
		entry->mem_obj->url, vary);
	    safe_free(request->vary_headers);
	    return VARY_CANCEL;
	}
	if (!has_vary) {
	    /* This is not a varying object */
	    return VARY_NONE;
	}
	/* virtual "vary" object found. Calculate the vary key and
	 * continue the search
	 */
	vary = httpMakeVaryMark(request, entry->mem_obj->reply);
	if (vary) {
	    request->vary_headers = xstrdup(vary);
	    return VARY_OTHER;
	} else {
	    /* Ouch.. we cannot handle this kind of variance */
	    /* XXX This cannot really happen, but just to be complete */
	    return VARY_CANCEL;
	}
    } else {
	if (!vary) {
	    vary = httpMakeVaryMark(request, entry->mem_obj->reply);
	    if (vary)
		request->vary_headers = xstrdup(vary);
	}
	if (!vary) {
	    /* Ouch.. we cannot handle this kind of variance */
	    /* XXX This cannot really happen, but just to be complete */
	    return VARY_CANCEL;
	} else if (strcmp(vary, entry->mem_obj->vary_headers) == 0) {
	    return VARY_MATCH;
	} else {
	    /* Oops.. we have already been here and still haven't
	     * found the requested variant. Bail out
	     */
	    debug(33, 1) ("varyEvaluateMatch: Oops. Not a Vary match on second attempt, '%s' '%s'\n",
		entry->mem_obj->url, vary);
	    return VARY_CANCEL;
	}
    }
}
