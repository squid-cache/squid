
/*
 * $Id: http.cc,v 1.270 1998/05/11 18:44:38 rousskov Exp $
 *
 * DEBUG: section 11    Hypertext Transfer Protocol (HTTP)
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

/*
 * Anonymizing patch by lutz@as-node.jena.thur.de
 * have a look into http-anon.c to get more informations.
 */

#include "squid.h"

static const char *const crlf = "\r\n";

enum {
    CCC_NOCACHE,
    CCC_NOSTORE,
    CCC_MAXAGE,
    CCC_MAXSTALE,
    CCC_MINFRESH,
    CCC_ONLYIFCACHED,
    CCC_ENUM_END
};

static CNCB httpConnectDone;
static CWCB httpSendComplete;
static CWCB httpSendRequestEntry;

static PF httpReadReply;
static PF httpSendRequest;
static PF httpStateFree;
static PF httpTimeout;
#if OLD_CODE
static void httpAppendRequestHeader(char *hdr, const char *line, size_t * sz, size_t max, int);
#endif
static void httpCacheNegatively(StoreEntry *);
static void httpMakePrivate(StoreEntry *);
static void httpMakePublic(StoreEntry *);
static STABH httpAbort;
static HttpStateData *httpBuildState(int, StoreEntry *, request_t *, peer *);
static int httpSocketOpen(StoreEntry *, request_t *);
static void httpRestart(HttpStateData *);
static int httpTryRestart(HttpStateData *);
static int httpCachableReply(HttpStateData *);

static void
httpStateFree(int fdnotused, void *data)
{
    HttpStateData *httpState = data;
    if (httpState == NULL)
	return;
    storeUnregisterAbort(httpState->entry);
    assert(httpState->entry->store_status != STORE_PENDING);
    storeUnlockObject(httpState->entry);
    if (httpState->reply_hdr) {
	memFree(MEM_8K_BUF, httpState->reply_hdr);
	httpState->reply_hdr = NULL;
    }
    requestUnlink(httpState->request);
    requestUnlink(httpState->orig_request);
    httpState->request = NULL;
    httpState->orig_request = NULL;
    cbdataFree(httpState);
}

int
httpCachable(method_t method)
{
    /* GET and HEAD are cachable. Others are not. */
    if (method != METHOD_GET && method != METHOD_HEAD)
	return 0;
    /* else cachable */
    return 1;
}

static void
httpTimeout(int fd, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 4) ("httpTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    assert(entry->store_status == STORE_PENDING);
    if (entry->mem_obj->inmem_hi == 0) {
	err = errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT);
	err->request = requestLink(httpState->orig_request);
	errorAppendEntry(entry, err);
    } else {
	storeAbort(entry, 0);
    }
    comm_close(fd);
}

/* This object can be cached for a long time */
static void
httpMakePublic(StoreEntry * entry)
{
    if (EBIT_TEST(entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(entry);
}

/* This object should never be cached at all */
static void
httpMakePrivate(StoreEntry * entry)
{
    storeExpireNow(entry);
    EBIT_CLR(entry->flag, ENTRY_CACHABLE);
    storeReleaseRequest(entry);	/* delete object when not used */
}

/* This object may be negatively cached */
static void
httpCacheNegatively(StoreEntry * entry)
{
    storeNegativeCache(entry);
    if (EBIT_TEST(entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(entry);
}

static int
httpCachableReply(HttpStateData * httpState)
{
    HttpReply *rep = httpState->entry->mem_obj->reply;
    HttpHeader *hdr = &rep->header;
    const int cc_mask = (rep->cache_control) ? rep->cache_control->mask : 0;
    if (EBIT_TEST(cc_mask, CC_PRIVATE))
	return 0;
    if (EBIT_TEST(cc_mask, CC_NO_CACHE))
	return 0;
    if (EBIT_TEST(httpState->request->flags, REQ_AUTH))
	if (!EBIT_TEST(cc_mask, CC_PROXY_REVALIDATE))
	    return 0;
    /*
     * Dealing with cookies is quite a bit more complicated
     * than this.  Ideally we should strip the cookie
     * header from the reply but still cache the reply body.
     * More confusion at draft-ietf-http-state-mgmt-05.txt.
     */
    /* With new headers the above stripping should be easy to do? @?@ */
    if (httpHeaderHas(hdr, HDR_SET_COOKIE))
	return 0;
    switch (httpState->entry->mem_obj->reply->sline.status) {
	/* Responses that are cacheable */
    case 200:			/* OK */
    case 203:			/* Non-Authoritative Information */
    case 300:			/* Multiple Choices */
    case 301:			/* Moved Permanently */
    case 410:			/* Gone */
	/* don't cache objects from peers w/o LMT, Date, or Expires */
	/* check that is it enough to check headers @?@ */
	if (rep->date > -1)
	    return 1;
	else if (rep->last_modified > -1)
	    return 1;
	else if (!httpState->peer)
	    return 1;
	/* @?@ (here and 302): invalid expires header compiles to squid_curtime */
	else if (rep->expires > -1)
	    return 1;
	else
	    return 0;
	/* NOTREACHED */
	break;
	/* Responses that only are cacheable if the server says so */
    case 302:			/* Moved temporarily */
	if (rep->expires > -1)
	    return 1;
	else
	    return 0;
	/* NOTREACHED */
	break;
/* @?@ should we replace these magic numbers with http_status enums? */
	/* Errors can be negatively cached */
    case 204:			/* No Content */
    case 305:			/* Use Proxy (proxy redirect) */
    case 400:			/* Bad Request */
    case 403:			/* Forbidden */
    case 404:			/* Not Found */
    case 405:			/* Method Now Allowed */
    case 414:			/* Request-URI Too Long */
    case 500:			/* Internal Server Error */
    case 501:			/* Not Implemented */
    case 502:			/* Bad Gateway */
    case 503:			/* Service Unavailable */
    case 504:			/* Gateway Timeout */
	return -1;
	/* NOTREACHED */
	break;
	/* Some responses can never be cached */
    case 206:			/* Partial Content -- Not yet supported */
    case 303:			/* See Other */
    case 304:			/* Not Modified */
    case 401:			/* Unauthorized */
    case 407:			/* Proxy Authentication Required */
    case 600:			/* Squid header parsing error */
    default:			/* Unknown status code */
	return 0;
	/* NOTREACHED */
	break;
    }
    /* NOTREACHED */
}

/* rewrite this later using new interfaces @?@ */
void
httpProcessReplyHeader(HttpStateData * httpState, const char *buf, int size)
{
    char *t = NULL;
    StoreEntry *entry = httpState->entry;
    int room;
    int hdr_len;
    HttpReply *reply = entry->mem_obj->reply;
    debug(11, 3) ("httpProcessReplyHeader: key '%s'\n",
	storeKeyText(entry->key));
    if (httpState->reply_hdr == NULL)
	httpState->reply_hdr = memAllocate(MEM_8K_BUF);
    if (httpState->reply_hdr_state == 0) {
	hdr_len = strlen(httpState->reply_hdr);
	room = 8191 - hdr_len;
	strncat(httpState->reply_hdr, buf, room < size ? room : size);
	hdr_len += room < size ? room : size;
	if (hdr_len > 4 && strncmp(httpState->reply_hdr, "HTTP/", 5)) {
	    debug(11, 3) ("httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", httpState->reply_hdr);
	    httpState->reply_hdr_state += 2;
	    reply->sline.status = 555;
	    return;
	}
	t = httpState->reply_hdr + hdr_len;
	/* headers can be incomplete only if object still arriving */
	if (!httpState->eof) {
	    size_t k = headersEnd(httpState->reply_hdr, 8192);
	    if (0 == k)
		return;		/* headers not complete */
	    t = httpState->reply_hdr + k;
	}
	*t = '\0';
	httpState->reply_hdr_state++;
    }
    if (httpState->reply_hdr_state == 1) {
	const Ctx ctx = ctx_enter(entry->mem_obj->url);
	httpState->reply_hdr_state++;
	debug(11, 9) ("GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    httpState->reply_hdr);
	/* Parse headers into reply structure */
	/* Old code never parsed headers if headersEnd failed, was it intentional ? @?@ @?@ */
	/* what happens if we fail to parse here? @?@ @?@ */
	httpReplyParse(reply, httpState->reply_hdr);	/* httpState->eof); */
	storeTimestampsSet(entry);
	/* Check if object is cacheable or not based on reply code */
	debug(11, 3) ("httpProcessReplyHeader: HTTP CODE: %d\n", reply->sline.status);
	switch (httpCachableReply(httpState)) {
	case 1:
	    httpMakePublic(entry);
	    break;
	case 0:
	    httpMakePrivate(entry);
	    break;
	case -1:
	    httpCacheNegatively(entry);
	    break;
	default:
	    assert(0);
	    break;
	}
	if (reply->cache_control && EBIT_TEST(reply->cache_control->mask, CC_PROXY_REVALIDATE))
	    EBIT_SET(entry->flag, ENTRY_REVALIDATE);
	if (EBIT_TEST(httpState->flags, HTTP_KEEPALIVE))
	    if (httpState->peer)
		httpState->peer->stats.n_keepalives_sent++;
	if (reply->keep_alive)
	    if (httpState->peer)
		httpState->peer->stats.n_keepalives_recv++;
	ctx_exit(ctx);
    }
}

static int
httpPconnTransferDone(HttpStateData * httpState)
{
    /* return 1 if we got the last of the data on a persistent connection */
    MemObject *mem = httpState->entry->mem_obj;
    HttpReply *reply = mem->reply;
    debug(11, 3) ("httpPconnTransferDone: FD %d\n", httpState->fd);
    /*
     * If we didn't send a keep-alive request header, then this
     * can not be a persistent connection.
     */
    if (!EBIT_TEST(httpState->flags, HTTP_KEEPALIVE))
	return 0;
    /*
     * What does the reply have to say about keep-alive?
     */
    if (!reply->keep_alive)
	return 0;
    debug(11, 5) ("httpPconnTransferDone: content_length=%d\n",
	reply->content_length);
    /*
     * Deal with gross HTTP stuff
     *    - If we haven't seen the end of the reply headers, we can't
     *      be persistent.
     *    - For "200 OK" check the content-length in the next block.
     *    - For "204 No Content" (even with content-length) we're done.
     *    - For "304 Not Modified" (even with content-length) we're done.
     *    - 1XX replies never have a body; we're done.
     *    - For HEAD requests with content-length we're done.
     *    - For all other replies, check content length in next block.
     */
    if (httpState->reply_hdr_state < 2)
	return 0;
    else if (reply->sline.status == HTTP_OK)
	(void) 0;		/* common case, continue */
    else if (reply->sline.status == HTTP_NO_CONTENT)
	return 1;
    else if (reply->sline.status == HTTP_NOT_MODIFIED)
	return 1;
    else if (reply->sline.status < HTTP_OK)
	return 1;
    else if (httpState->request->method == METHOD_HEAD)
	return 1;
    /*
     * If there is no content-length, then we can't be
     * persistent.  If there is a content length, then we must
     * wait until we've seen the end of the body.
     */
    if (reply->content_length < 0)
	return 0;
    else if (mem->inmem_hi < reply->content_length + reply->hdr_sz)
	return 0;
    else
	return 1;
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
/* XXX this function is too long! */
static void
httpReadReply(int fd, void *data)
{
    HttpStateData *httpState = data;
    LOCAL_ARRAY(char, buf, SQUID_TCP_SO_RCVBUF);
    StoreEntry *entry = httpState->entry;
    const request_t *request = httpState->request;
    int len;
    int bin;
    int clen;
    ErrorState *err;
    if (protoAbortFetch(entry)) {
	storeAbort(entry, 0);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->inmem_hi;
    errno = 0;
    len = read(fd, buf, SQUID_TCP_SO_RCVBUF);
    debug(11, 5) ("httpReadReply: FD %d: len %d.\n", fd, len);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
	kb_incr(&Counter.server.all.kbytes_in, len);
	kb_incr(&Counter.server.http.kbytes_in, len);
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Http.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Http.read_hist[bin]++;
    }
    if (!httpState->reply_hdr && len > 0) {
	/* Skip whitespace */
	while (len > 0 && isspace(*buf))
	    xmemmove(buf, buf + 1, len--);
	if (len == 0) {
	    /* Continue to read... */
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	    return;
	}
    }
    if (len < 0) {
	debug(50, 2) ("httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (ignoreErrno(errno)) {
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	} else if (entry->mem_obj->inmem_hi == 0 && httpTryRestart(httpState)) {
	    httpRestart(httpState);
	} else if (clen == 0) {
	    err = errorCon(ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR);
	    err->xerrno = errno;
	    err->request = requestLink(httpState->orig_request);
	    errorAppendEntry(entry, err);
	    comm_close(fd);
	} else {
	    storeAbort(entry, 0);
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->inmem_hi == 0) {
	if (httpTryRestart(httpState)) {
	    httpRestart(httpState);
	} else {
	    httpState->eof = 1;
	    err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE);
	    err->xerrno = errno;
	    err->request = requestLink(httpState->orig_request);
	    errorAppendEntry(entry, err);
	    comm_close(fd);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	httpState->eof = 1;
	if (httpState->reply_hdr_state < 2)
	    /*
	     * Yes Henrik, there is a point to doing this.  When we
	     * called httpProcessReplyHeader() before, we didn't find
	     * the end of headers, but now we are definately at EOF, so
	     * we want to process the reply headers.
	     */
	    httpProcessReplyHeader(httpState, buf, len);
	storeComplete(entry);	/* deallocates mem_obj->request */
	comm_close(fd);
    } else {
	if (httpState->reply_hdr_state < 2)
	    httpProcessReplyHeader(httpState, buf, len);
	storeAppend(entry, buf, len);
	if (httpPconnTransferDone(httpState)) {
	    /* yes we have to clear all these! */
	    commSetDefer(fd, NULL, NULL);
	    commSetTimeout(fd, -1, NULL, NULL);
	    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
	    comm_remove_close_handler(fd, httpStateFree, httpState);
	    storeComplete(entry);	/* deallocates mem_obj->request */
	    pconnPush(fd, request->host, request->port);
	    httpState->fd = -1;
	    httpStateFree(-1, httpState);
	} else {
	    /* Wait for EOF condition */
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	}
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
httpSendComplete(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&Counter.server.all.kbytes_out, size);
	kb_incr(&Counter.server.http.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	err = errorCon(ERR_WRITE_ERROR, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->request = requestLink(httpState->orig_request);
	errorAppendEntry(entry, err);
	comm_close(fd);
	return;
    } else {
	/* Schedule read reply. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    httpReadReply,
	    httpState, 0);
	commSetDefer(fd, protoCheckDeferRead, entry);
    }
}

#if OLD_CODE
static void
httpAppendRequestHeader(char *hdr, const char *line, size_t * sz, size_t max, int check)
{
    size_t n = *sz + strlen(line) + 2;
    if (n >= max)
	return;
    if (check) {
	if (Config.onoff.anonymizer == ANONYMIZER_PARANOID) {
	    if (!httpAnonAllowed(line))
		return;
	} else if (Config.onoff.anonymizer == ANONYMIZER_STANDARD) {
	    if (httpAnonDenied(line))
		return;
	}
    }
    /* allowed header, explicitly known to be not dangerous */
    debug(11, 5) ("httpAppendRequestHeader: %s\n", line);
    strcpy(hdr + (*sz), line);
    strcat(hdr + (*sz), crlf);
    *sz = n;
}
#endif

/*
 * build request headers and append them to a given MemBuf 
 * used by httpBuildRequestPrefix()
 * note: calls httpHeaderInit(), the caller is responsible for Clean()-ing
 */
static void
httpBuildRequestHeader(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    HttpHeader *hdr_out,
    int cfd,
    int flags)
{
    /* building buffer for complex strings */
    #define BBUF_SZ (MAX_URL+32)
    LOCAL_ARRAY(char, bbuf, BBUF_SZ);
    String strConnection = StringNull;
    const HttpHeader *hdr_in = &orig_request->header;
    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;

    assert(orig_request->prefix != NULL);
    debug(11, 3) ("httpBuildRequestHeader:\n%s", orig_request->prefix);
    httpHeaderInit(hdr_out);
    
    /* append our IMS header */
    if (entry && entry->lastmod && request->method == METHOD_GET)
	httpHeaderPutTime(hdr_out, HDR_IF_MODIFIED_SINCE, entry->lastmod);

    strConnection = httpHeaderGetList(hdr_in, HDR_CONNECTION);
    while ((e = httpHeaderGetEntry(hdr_in, &pos))) {
	debug(11, 5) ("httpBuildRequestHeader: %s: %s\n",
	    strBuf(e->name), strBuf(e->value));
	if (!httpRequestHdrAllowed(e, &strConnection))
	    continue;
	switch (e->id) {
	case HDR_PROXY_AUTHORIZATION:
	    /* If we're not going to do proxy auth, then it must be passed on */
	    if (!EBIT_TEST(request->flags, REQ_USED_PROXY_AUTH))
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    break;
	case HDR_HOST:
	    /* Don't use client's Host: header for redirected requests */
	    if (!EBIT_TEST(request->flags, REQ_REDIRECTED))
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    break;
	case HDR_IF_MODIFIED_SINCE:
	    /* append unless we added our own;
	     * note: at most one client's ims header can pass through */
	    if (!httpHeaderHas(hdr_out, HDR_IF_MODIFIED_SINCE))
		httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	    break;
	case HDR_MAX_FORWARDS:
	    if (orig_request->method == METHOD_TRACE) {
		/* sacrificing efficiency over clarity, etc. */
		const int hops = httpHeaderGetInt(hdr_in, HDR_MAX_FORWARDS);
		if (hops > 0)
		    httpHeaderPutInt(hdr_out, HDR_MAX_FORWARDS, hops-1);
	    }
	    break;
	case HDR_PROXY_CONNECTION:
	case HDR_CONNECTION:
	case HDR_VIA:
	case HDR_X_FORWARDED_FOR:
	case HDR_CACHE_CONTROL:
	    /* append these after the loop if needed */
	    break;
	default:
	    /* pass on all other header fields */
	    httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
	}
    }

    /* append fake user agent if configured and 
     * the real one is not supplied by the client */
    if (Config.fake_ua && !httpHeaderHas(hdr_out, HDR_USER_AGENT))
	httpHeaderPutStr(hdr_out, HDR_USER_AGENT, Config.fake_ua);

    /* append Via */
    {
	String strVia = httpHeaderGetList(hdr_in, HDR_VIA);
	snprintf(bbuf, BBUF_SZ, "%3.1f %s", orig_request->http_ver, ThisCache);
	strListAdd(&strVia, bbuf, ',');
	httpHeaderPutStr(hdr_out, HDR_VIA, strBuf(strVia));
	stringClean(&strVia);
    }
    /* append X-Forwarded-For */
    {
	String strFwd = httpHeaderGetList(hdr_in, HDR_X_FORWARDED_FOR);
	strListAdd(&strFwd, (cfd < 0 ? "unknown" : fd_table[cfd].ipaddr), ',');
	httpHeaderPutStr(hdr_out, HDR_X_FORWARDED_FOR, strBuf(strFwd));
	stringClean(&strFwd);
    }
    /* append Host if not there already */
    if (!httpHeaderHas(hdr_out, HDR_HOST)) {
	/* use port# only if not default */
	if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
	    httpHeaderPutStr(hdr_out, HDR_HOST, orig_request->host);
	} else {
	    snprintf(bbuf, BBUF_SZ, "%s:%d",
		orig_request->host, (int) orig_request->port);
	    httpHeaderPutStr(hdr_out, HDR_HOST, bbuf);
	}
    }
    /* append Cache-Control, add max-age if not there already */
    {
	HttpHdrCc *cc = httpHeaderGetCc(hdr_in);
	if (!cc)
	    cc = httpHdrCcCreate();
	if (!EBIT_TEST(cc->mask, CC_MAX_AGE)) {
	    const char *url = entry ? storeUrl(entry) : urlCanonical(orig_request, NULL);
	    httpHdrCcSetMaxAge(cc, getMaxAge(url));
	    if (strLen(request->urlpath))
		assert(strstr(url, strBuf(request->urlpath)));
	}
	httpHeaderPutCc(hdr_out, cc);
	httpHdrCcDestroy(cc);
    }
    /* maybe append Connection: keep-alive */
    if (EBIT_TEST(flags, HTTP_KEEPALIVE)) {
	if (EBIT_TEST(flags, HTTP_PROXYING)) {
	    httpHeaderPutStr(hdr_out, HDR_PROXY_CONNECTION, "keep-alive");
	} else {
	    httpHeaderPutStr(hdr_out, HDR_CONNECTION, "keep-alive");
	}
    }
    stringClean(&strConnection);
}

/* build request prefix and append it to a given MemBuf; 
 * return the length of the prefix */
size_t
httpBuildRequestPrefix(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    MemBuf *mb,
    int cfd,
    int flags)
{
    const int offset = mb->size;
    memBufPrintf(mb, "%s %s HTTP/1.0\r\n",
	RequestMethodStr[request->method],
	strLen(request->urlpath) ? strBuf(request->urlpath) : "/");
    /* build and pack headers */
    {
	HttpHeader hdr;
	Packer p;
	httpBuildRequestHeader(request, orig_request, entry, &hdr, cfd, flags);
	packerToMemInit(&p, mb);
	httpHeaderPackInto(&hdr, &p);
	httpHeaderClean(&hdr);
	packerClean(&p);
    }
    /* append header terminator */
    memBufAppend(mb, "\r\n", 2);
    return mb->size - offset;
}

/* This will be called when connect completes. Write request. */
static void
httpSendRequest(int fd, void *data)
{
    HttpStateData *httpState = data;
    MemBuf mb;
    request_t *req = httpState->request;
    StoreEntry *entry = httpState->entry;
    int cfd;
    peer *p = httpState->peer;
    CWCB *sendHeaderDone;

    debug(11, 5) ("httpSendRequest: FD %d: httpState %p.\n", fd, httpState);

    if (pumpMethod(req->method))
	sendHeaderDone = httpSendRequestEntry;
    else
	sendHeaderDone = httpSendComplete;

    if (!opt_forwarded_for)
	cfd = -1;
    else if (entry->mem_obj == NULL)
	cfd = -1;
    else
	cfd = entry->mem_obj->fd;
    assert(-1 == cfd || FD_SOCKET == fd_table[cfd].type);
    if (p != NULL)
	EBIT_SET(httpState->flags, HTTP_PROXYING);
    /*
     * Is keep-alive okay for all request methods?
     */
    if (p == NULL)
	EBIT_SET(httpState->flags, HTTP_KEEPALIVE);
    else if (p->stats.n_keepalives_sent < 10)
	EBIT_SET(httpState->flags, HTTP_KEEPALIVE);
    else if ((double) p->stats.n_keepalives_recv / (double) p->stats.n_keepalives_sent > 0.50)
	EBIT_SET(httpState->flags, HTTP_KEEPALIVE);
    memBufDefInit(&mb);
    httpBuildRequestPrefix(req,
	httpState->orig_request,
	entry,
	&mb,
	cfd,
	httpState->flags);
    debug(11, 6) ("httpSendRequest: FD %d:\n%s\n", fd, mb.buf);
    comm_write_mbuf(fd, mb, sendHeaderDone, httpState);
}

static int
httpSocketOpen(StoreEntry * entry, request_t * request)
{
    int fd;
    ErrorState *err;
    fd = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	storeUrl(entry));
    if (fd < 0) {
	debug(50, 4) ("httpSocketOpen: %s\n", xstrerror());
	err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->request = requestLink(request);
	errorAppendEntry(entry, err);
    }
    return fd;
}

static HttpStateData *
httpBuildState(int fd, StoreEntry * entry, request_t * orig_request, peer * e)
{
    HttpStateData *httpState = memAllocate(MEM_HTTP_STATE_DATA);
    request_t *request;
    storeLockObject(entry);
    cbdataAdd(httpState, MEM_HTTP_STATE_DATA);
    httpState->entry = entry;
    httpState->fd = fd;
    if (e) {
	request = requestCreate(
	    orig_request->method, PROTO_NONE, storeUrl(entry));
	xstrncpy(request->host, e->host, SQUIDHOSTNAMELEN);
	request->port = e->http_port;
	httpState->request = requestLink(request);
	httpState->peer = e;
	httpState->orig_request = requestLink(orig_request);
	EBIT_SET(request->flags, REQ_PROXYING);
    } else {
	httpState->request = requestLink(orig_request);
	httpState->orig_request = requestLink(orig_request);
    }
    /* register the handler to free HTTP state data when the FD closes */
    comm_add_close_handler(httpState->fd, httpStateFree, httpState);
    storeRegisterAbort(entry, httpAbort, httpState);
    return httpState;
}

void
httpStart(request_t * request, StoreEntry * entry, peer * e)
{
    HttpStateData *httpState;
    int fd;
    debug(11, 3) ("httpStart: \"%s %s\"\n",
	RequestMethodStr[request->method], storeUrl(entry));
    Counter.server.all.requests++;
    Counter.server.http.requests++;
    if (e) {
	if (EBIT_TEST(e->options, NEIGHBOR_PROXY_ONLY))
	    storeReleaseRequest(entry);
	if ((fd = pconnPop(e->host, e->http_port)) >= 0) {
	    debug(11, 3) ("httpStart: reusing pconn FD %d\n", fd);
	    httpState = httpBuildState(fd, entry, request, e);
	    commSetTimeout(httpState->fd,
		Config.Timeout.connect,
		httpTimeout,
		httpState);
	    httpConnectDone(fd, COMM_OK, httpState);
	    return;
	}
    } else {
	if ((fd = pconnPop(request->host, request->port)) >= 0) {
	    debug(11, 3) ("httpStart: reusing pconn FD %d\n", fd);
	    httpState = httpBuildState(fd, entry, request, e);
	    commSetTimeout(httpState->fd,
		Config.Timeout.connect,
		httpTimeout,
		httpState);
	    httpConnectDone(fd, COMM_OK, httpState);
	    return;
	}
    }
    if ((fd = httpSocketOpen(entry, request)) < 0)
	return;
    httpState = httpBuildState(fd, entry, request, e);
    commSetTimeout(httpState->fd,
	Config.Timeout.connect,
	httpTimeout,
	httpState);
    commConnectStart(httpState->fd,
	httpState->request->host,
	httpState->request->port,
	httpConnectDone,
	httpState);
}

static int
httpTryRestart(HttpStateData * httpState)
{
    /*
     * We only retry the request if it looks like it was
     * on a persistent/pipelined connection
     */
    if (fd_table[httpState->fd].uses < 2)
	return 0;
    if (pumpMethod(httpState->orig_request->method))
	if (0 == pumpRestart(httpState->orig_request))
	    return 0;
    return 1;
}

static void
httpRestart(HttpStateData * httpState)
{
    /* restart a botched request from a persistent connection */
    debug(11, 2) ("Retrying HTTP request for %s\n", storeUrl(httpState->entry));
    if (pumpMethod(httpState->orig_request->method)) {
	debug(11, 1) ("Potential Coredump: httpRestart %s %s\n",
	    RequestMethodStr[httpState->orig_request->method],
	    storeUrl(httpState->entry));
    }
    if (httpState->fd >= 0) {
	comm_remove_close_handler(httpState->fd, httpStateFree, httpState);
	comm_close(httpState->fd);
	httpState->fd = -1;
    }
    httpState->fd = httpSocketOpen(httpState->entry, httpState->orig_request);
    if (httpState->fd < 0)
	return;
    comm_add_close_handler(httpState->fd, httpStateFree, httpState);
    commSetTimeout(httpState->fd,
	Config.Timeout.connect,
	httpTimeout,
	httpState);
    commConnectStart(httpState->fd,
	httpState->request->host,
	httpState->request->port,
	httpConnectDone,
	httpState);
}

static void
httpConnectDone(int fd, int status, void *data)
{
    HttpStateData *httpState = data;
    request_t *request = httpState->request;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    if (status == COMM_ERR_DNS) {
	debug(11, 4) ("httpConnectDone: Unknown host: %s\n", request->host);
	err = errorCon(ERR_DNS_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->request = requestLink(httpState->orig_request);
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else if (status != COMM_OK) {
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->host = xstrdup(request->host);
	err->port = request->port;
	err->request = requestLink(httpState->orig_request);
	errorAppendEntry(entry, err);
	if (httpState->peer)
	    peerCheckConnectStart(httpState->peer);
	comm_close(fd);
    } else {
	fd_note(fd, storeUrl(entry));
	fd_table[fd].uses++;
	commSetSelect(fd, COMM_SELECT_WRITE, httpSendRequest, httpState, 0);
	commSetTimeout(fd, Config.Timeout.read, httpTimeout, httpState);
    }
}

static void
httpAbort(void *data)
{
    HttpStateData *httpState = data;
    debug(11, 2) ("httpAbort: %s\n", storeUrl(httpState->entry));
    comm_close(httpState->fd);
}

static void
httpSendRequestEntry(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendRequestEntry: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&Counter.server.all.kbytes_out, size);
	kb_incr(&Counter.server.http.kbytes_out, size);
    }
    if (errflag == COMM_ERR_CLOSING)
	return;
    if (errflag) {
	err = errorCon(ERR_WRITE_ERROR, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->request = requestLink(httpState->orig_request);
	errorAppendEntry(entry, err);
	comm_close(fd);
	return;
    }
    pumpStart(fd, entry, httpState->orig_request, httpSendComplete, httpState);
}
