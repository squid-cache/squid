
/*
 * $Id: client_side.cc,v 1.139 1997/11/03 22:43:08 wessels Exp $
 *
 * DEBUG: section 33    Client-side Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

static RH clientRedirectDone;
static STCB icpHandleIMSReply;
static int clientGetsOldEntry(StoreEntry * new, StoreEntry * old, request_t * request);
static int checkAccelOnly(clientHttpRequest *);

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
    if (http->accel)
	return 0;
    return 1;
}

void
clientAccessCheck(void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn = http->conn;
    char *browser;
    if (Config.onoff.ident_lookup && conn->ident.state == IDENT_NONE) {
	identStart(-1, conn, clientAccessCheck);
	return;
    }
    if (checkAccelOnly(http)) {
	clientAccessCheckDone(0, http);
	return;
    }
    browser = mime_get_header(http->request->headers, "User-Agent");
    http->acl_checklist = aclChecklistCreate(Config.accessList.http,
	http->request,
	conn->peer.sin_addr,
	browser,
	conn->ident.ident);
    aclNBCheck(http->acl_checklist, clientAccessCheckDone, http);
}

void
clientAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn = http->conn;
    int fd = conn->fd;
    char *redirectUrl = NULL;
    ErrorState *err = NULL;
    debug(33, 5) ("clientAccessCheckDone: '%s' answer=%d\n", http->url, answer);
    http->acl_checklist = NULL;
    if (answer) {
	urlCanonical(http->request, http->url);
	if (http->redirect_state != REDIRECT_NONE)
	    fatal_dump("clientAccessCheckDone: wrong redirect_state");
	http->redirect_state = REDIRECT_PENDING;
	redirectStart(http, clientRedirectDone, http);
    } else {
	debug(33, 5) ("Access Denied: %s\n", http->url);
	redirectUrl = aclGetDenyInfoUrl(&Config.denyInfoList, AclMatchedName);
	if (redirectUrl) {
	    err = errorCon(ERR_ACCESS_DENIED, HTTP_MOVED_TEMPORARILY);
	    err->request = requestLink(http->request);
	    err->src_addr = http->conn->peer.sin_addr;
	    err->redirect_url = xstrdup(redirectUrl);
	    errorSend(fd, err);
	} else {
	    /* NOTE: don't use HTTP_UNAUTHORIZED because then the
	     * stupid browser wants us to authenticate */
	    err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	    err->request = requestLink(http->request);
	    err->src_addr = http->conn->peer.sin_addr;
	    errorSend(fd, err);
	}
    }
}

static void
clientRedirectDone(void *data, char *result)
{
    clientHttpRequest *http = data;
    int fd = http->conn->fd;
    size_t l;
    request_t *new_request = NULL;
    request_t *old_request = http->request;
    debug(33, 5) ("clientRedirectDone: '%s' result=%s\n", http->url,
	result ? result : "NULL");
    if (http->redirect_state != REDIRECT_PENDING)
	fatal_dump("clientRedirectDone: wrong redirect_state");
    http->redirect_state = REDIRECT_DONE;
    if (result)
	new_request = urlParse(old_request->method, result);
    if (new_request) {
	safe_free(http->url);
	/* need to malloc because the URL returned by the redirector might
	 * not be big enough to append the local domain
	 * -- David Lamkin drl@net-tel.co.uk */
	l = strlen(result) + Config.appendDomainLen + 5;
	http->url = xcalloc(l, 1);
	xstrncpy(http->url, result, l);
	new_request->http_ver = old_request->http_ver;
	new_request->headers = old_request->headers;
	new_request->headers_sz = old_request->headers_sz;
	requestUnlink(old_request);
	http->request = requestLink(new_request);
	urlCanonical(http->request, http->url);
    }
    icpParseRequestHeaders(http);
    fd_note(fd, http->url);
    icpProcessRequest(fd, http);
}

void
icpProcessExpired(int fd, void *data)
{
    clientHttpRequest *http = data;
    char *url = http->url;
    StoreEntry *entry = NULL;

    debug(33, 3) ("icpProcessExpired: FD %d '%s'\n", fd, http->url);

    BIT_SET(http->request->flags, REQ_REFRESH);
    http->old_entry = http->entry;
    entry = storeCreateEntry(url,
	http->log_url,
	http->request->flags,
	http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    storeClientListAdd(entry, http);
    storeClientListAdd(http->old_entry, http);

    entry->lastmod = http->old_entry->lastmod;
    debug(33, 5) ("icpProcessExpired: setting lmt = %d\n",
	entry->lastmod);

    entry->refcount++;		/* EXPIRED CASE */
    http->entry = entry;
    http->out.offset = 0;
    protoDispatch(fd, http->entry, http->request);
    /* Register with storage manager to receive updates when data comes in. */
    storeClientCopy(entry,
	http->out.offset,
	http->out.offset,
	4096,
	get_free_4k_page(),
	icpHandleIMSReply,
	http);
}

static int
clientGetsOldEntry(StoreEntry * new_entry, StoreEntry * old_entry, request_t * request)
{
    /* If the reply is anything but "Not Modified" then
     * we must forward it to the client */
    if (new_entry->mem_obj->reply->code != 304) {
	debug(33, 5) ("clientGetsOldEntry: NO, reply=%d\n", new_entry->mem_obj->reply->code);
	return 0;
    }
    /* If the client did not send IMS in the request, then it
     * must get the old object, not this "Not Modified" reply */
    if (!BIT_TEST(request->flags, REQ_IMS)) {
	debug(33, 5) ("clientGetsOldEntry: YES, no client IMS\n");
	return 1;
    }
    /* If the client IMS time is prior to the entry LASTMOD time we
     * need to send the old object */
    if (modifiedSince(old_entry, request)) {
	debug(33, 5) ("clientGetsOldEntry: YES, modified since %d\n", request->ims);
	return 1;
    }
    debug(33, 5) ("clientGetsOldEntry: NO, new one is fine\n");
    return 0;
}



static void
icpHandleIMSReply(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    int fd = http->conn->fd;
    StoreEntry *entry = http->entry;
    MemObject *mem = entry->mem_obj;
    const char *url = storeUrl(entry);
    int unlink_request = 0;
    StoreEntry *oldentry;
    debug(33, 3) ("icpHandleIMSReply: FD %d '%s'\n", fd, url);
    put_free_4k_page(buf);
    buf = NULL;
    /* unregister this handler */
    if (size < 0 || entry->store_status == STORE_ABORTED) {
	debug(33, 3) ("icpHandleIMSReply: ABORTED '%s'\n", url);
	/* We have an existing entry, but failed to validate it */
	/* Its okay to send the old one anyway */
	http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	storeUnregister(entry, http);
	storeUnlockObject(entry);
	entry = http->entry = http->old_entry;
	entry->refcount++;
    } else if (mem->reply->code == 0) {
	debug(33, 3) ("icpHandleIMSReply: Incomplete headers for '%s'\n", url);
	storeClientCopy(entry,
	    http->out.offset + size,
	    http->out.offset,
	    4096,
	    get_free_4k_page(),
	    icpHandleIMSReply,
	    http);
	return;
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
	memcpy(oldentry->mem_obj->reply, entry->mem_obj->reply, sizeof(struct _http_reply));
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
	if (mem->reply->code == 304) {
	    http->old_entry->timestamp = squid_curtime;
	    http->old_entry->refcount++;
	    http->log_type = LOG_TCP_REFRESH_HIT;
	}
	storeUnregister(http->old_entry, http);
	storeUnlockObject(http->old_entry);
    }
    http->old_entry = NULL;	/* done with old_entry */
    /* use clientCacheHit() here as the callback because we might
     * be swapping in from disk, and the file might not really be
     * there */
    storeClientCopy(entry,
	http->out.offset,
	http->out.offset,
	4096,
	get_free_4k_page(),
	clientCacheHit,
	http);
}

int
modifiedSince(StoreEntry * entry, request_t * request)
{
    int object_length;
    MemObject *mem = entry->mem_obj;
    debug(33, 3) ("modifiedSince: '%s'\n", storeUrl(entry));
    if (entry->lastmod < 0)
	return 1;
    /* Find size of the object */
    if (mem->reply->content_length)
	object_length = mem->reply->content_length;
    else
	object_length = entry->object_len - mem->reply->hdr_sz;
    if (entry->lastmod > request->ims) {
	debug(33, 3) ("--> YES: entry newer than client\n");
	return 1;
    } else if (entry->lastmod < request->ims) {
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

char *
clientConstructTraceEcho(clientHttpRequest * http)
{
    LOCAL_ARRAY(char, line, 256);
    LOCAL_ARRAY(char, buf, 8192);
    size_t len;
    memset(buf, '\0', 8192);
    snprintf(buf, 8192, "HTTP/1.0 200 OK\r\n");
    snprintf(line, 256, "Date: %s\r\n", mkrfc1123(squid_curtime));
    strcat(buf, line);
    snprintf(line, 256, "Server: Squid/%s\r\n", SQUID_VERSION);
    strcat(buf, line);
    snprintf(line, 256, "Content-Type: message/http\r\n");
    strcat(buf, line);
    strcat(buf, "\r\n");
    len = strlen(buf);
    httpBuildRequestHeader(http->request,
	http->request,
	NULL,			/* entry */
	NULL,			/* in_len */
	buf + len,
	8192 - len,
	http->conn->fd,
	0);			/* flags */
    http->log_type = LOG_TCP_MISS;
    http->http_code = HTTP_OK;
    return buf;
}

void
clientPurgeRequest(clientHttpRequest * http)
{
    int fd = http->conn->fd;
    char *msg;
    StoreEntry *entry;
    ErrorState *err = NULL;
    const cache_key *k;
    debug(33, 3) ("Config.onoff.enable_purge = %d\n", Config.onoff.enable_purge);
    if (!Config.onoff.enable_purge) {
	err = errorCon(ERR_ACCESS_DENIED, HTTP_FORBIDDEN);
	err->request = requestLink(http->request);
	err->src_addr = http->conn->peer.sin_addr;
	errorSend(fd, err);
	return;
    }
    http->log_type = LOG_TCP_MISS;
    k = storeKeyPublic(http->url, METHOD_GET);
    if ((entry = storeGet(k)) == NULL) {
	http->http_code = HTTP_NOT_FOUND;
    } else {
	storeRelease(entry);
	http->http_code = HTTP_OK;
    }
    msg = httpReplyHeader(1.0, http->http_code, NULL, 0, 0, -1);
    if (strlen(msg) < 8190)
	strcat(msg, "\r\n");
    comm_write(fd, xstrdup(msg), strlen(msg), clientWriteComplete, http, xfree);
}

int
checkNegativeHit(StoreEntry * e)
{
    if (!BIT_TEST(e->flag, ENTRY_NEGCACHED))
	return 0;
    if (e->expires <= squid_curtime)
	return 0;
    if (e->store_status != STORE_OK)
	return 0;
    return 1;
}
