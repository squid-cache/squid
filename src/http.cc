/*
 * $Id: http.cc,v 1.193 1997/10/22 05:50:30 wessels Exp $
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

typedef enum {
    SCC_PUBLIC,
    SCC_PRIVATE,
    SCC_NOCACHE,
    SCC_NOSTORE,
    SCC_NOTRANSFORM,
    SCC_MUSTREVALIDATE,
    SCC_PROXYREVALIDATE,
    SCC_MAXAGE,
    SCC_ENUM_END
} http_server_cc_t;

enum {
    CCC_NOCACHE,
    CCC_NOSTORE,
    CCC_MAXAGE,
    CCC_MAXSTALE,
    CCC_MINFRESH,
    CCC_ONLYIFCACHED,
    CCC_ENUM_END
};

typedef enum {
    HDR_ACCEPT,
    HDR_AGE,
    HDR_CONTENT_LENGTH,
    HDR_CONTENT_MD5,
    HDR_CONTENT_TYPE,
    HDR_DATE,
    HDR_ETAG,
    HDR_EXPIRES,
    HDR_HOST,
    HDR_IMS,
    HDR_LAST_MODIFIED,
    HDR_MAX_FORWARDS,
    HDR_PUBLIC,
    HDR_RETRY_AFTER,
    HDR_SET_COOKIE,
    HDR_UPGRADE,
    HDR_WARNING,
    HDR_MISC_END
} http_hdr_misc_t;

static char *HttpServerCCStr[] =
{
    "public",
    "private",
    "no-cache",
    "no-store",
    "no-transform",
    "must-revalidate",
    "proxy-revalidate",
    "max-age",
    "NONE"
};

static char *HttpHdrMiscStr[] =
{
    "Accept",
    "Age",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Etag",
    "Expires",
    "Host",
    "If-Modified-Since",
    "Last-Modified",
    "Max-Forwards",
    "Public",
    "Retry-After",
    "Set-Cookie",
    "Upgrade",
    "Warning",
    "NONE"
};

static struct {
    int parsed;
    int misc[HDR_MISC_END];
    int cc[SCC_ENUM_END];
} ReplyHeaderStats;

static CNCB httpConnectDone;
static CWCB httpSendComplete;
static PF httpReadReply;
static PF httpSendRequest;
static PF httpStateFree;
static PF httpTimeout;
static void httpAppendRequestHeader _PARAMS((char *hdr, const char *line, size_t * sz, size_t max, int));
static void httpCacheNegatively _PARAMS((StoreEntry *));
static void httpMakePrivate _PARAMS((StoreEntry *));
static void httpMakePublic _PARAMS((StoreEntry *));
static char *httpStatusString _PARAMS((int status));
static STABH httpAbort;
static HttpStateData *httpBuildState _PARAMS((int, StoreEntry *, request_t *, peer *));
static int httpSocketOpen _PARAMS((StoreEntry *, request_t *));
static void httpRestart _PARAMS((HttpStateData *));

static void
httpStateFree(int fd, void *data)
{
    HttpStateData *httpState = data;
    if (httpState == NULL)
	return;
    storeUnregisterAbort(httpState->entry);
    storeUnlockObject(httpState->entry);
    if (httpState->reply_hdr) {
	put_free_8k_page(httpState->reply_hdr);
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
    debug(11, 4) ("httpTimeout: FD %d: '%s'\n", fd, entry->url);
    if (entry->mem_obj->inmem_hi == 0) {
	err = xcalloc(1, sizeof(ErrorState));
	err->type = ERR_READ_TIMEOUT;
	err->http_status = HTTP_GATEWAY_TIMEOUT;
	err->request = requestLink(httpState->request);
	errorAppendEntry(entry, err);
    }
    storeAbort(entry, 0);
    comm_close(fd);
}

/* This object can be cached for a long time */
static void
httpMakePublic(StoreEntry * entry)
{
    if (BIT_TEST(entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(entry);
}

/* This object should never be cached at all */
static void
httpMakePrivate(StoreEntry * entry)
{
    storeExpireNow(entry);
    BIT_RESET(entry->flag, ENTRY_CACHABLE);
    storeReleaseRequest(entry);	/* delete object when not used */
}

/* This object may be negatively cached */
static void
httpCacheNegatively(StoreEntry * entry)
{
    storeNegativeCache(entry);
    if (BIT_TEST(entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(entry);
}


/* Build a reply structure from HTTP reply headers */
void
httpParseReplyHeaders(const char *buf, struct _http_reply *reply)
{
    char *headers = get_free_4k_page();
    char *line;
    char *end;
    char *s = NULL;
    char *t;
    time_t delta;
    size_t l;

    reply->code = 600;
    ReplyHeaderStats.parsed++;
    xstrncpy(headers, buf, 4096);
    end = mime_headers_end(headers);
    if (end == NULL) {
	t = headers;
	if (!strncasecmp(t, "HTTP/", 5)) {
	    reply->version = atof(t + 5);
	    if ((t = strchr(t, ' ')))
		reply->code = atoi(++t);
	}
	put_free_4k_page(headers);
	return;
    }
    reply->hdr_sz = end - headers;
    line = get_free_4k_page();
    for (s = headers; s < end; s += strcspn(s, crlf), s += strspn(s, crlf)) {
	l = strcspn(s, crlf) + 1;
	if (l > 4096)
	    l = 4096;
	xstrncpy(line, s, l);
	t = line;
	debug(11, 3) ("httpParseReplyHeaders: %s\n", t);
	if (!strncasecmp(t, "HTTP/", 5)) {
	    reply->version = atof(t + 5);
	    if ((t = strchr(t, ' ')))
		reply->code = atoi(++t);
	} else if (!strncasecmp(t, "Content-type:", 13)) {
	    for (t += 13; isspace(*t); t++);
	    if ((l = strcspn(t, ";\t ")) > 0)
		*(t + l) = '\0';
	    xstrncpy(reply->content_type, t, HTTP_REPLY_FIELD_SZ);
	    ReplyHeaderStats.misc[HDR_CONTENT_TYPE]++;
	} else if (!strncasecmp(t, "Content-length:", 15)) {
	    for (t += 15; isspace(*t); t++);
	    reply->content_length = atoi(t);
	    ReplyHeaderStats.misc[HDR_CONTENT_LENGTH]++;
	} else if (!strncasecmp(t, "Date:", 5)) {
	    for (t += 5; isspace(*t); t++);
	    reply->date = parse_rfc1123(t);
	    ReplyHeaderStats.misc[HDR_DATE]++;
	} else if (!strncasecmp(t, "Expires:", 8)) {
	    for (t += 8; isspace(*t); t++);
	    reply->expires = parse_rfc1123(t);
	    /*
	     * The HTTP/1.0 specs says that robust implementations
	     * should consider bad or malformed Expires header as
	     * equivalent to "expires immediately."
	     */
	    if (reply->expires == -1)
		reply->expires = squid_curtime;
	    ReplyHeaderStats.misc[HDR_EXPIRES]++;
	} else if (!strncasecmp(t, "Last-Modified:", 14)) {
	    for (t += 14; isspace(*t); t++);
	    reply->last_modified = parse_rfc1123(t);
	    ReplyHeaderStats.misc[HDR_LAST_MODIFIED]++;
	} else if (!strncasecmp(t, "Accept:", 7)) {
	    ReplyHeaderStats.misc[HDR_ACCEPT]++;
	} else if (!strncasecmp(t, "Age:", 4)) {
	    ReplyHeaderStats.misc[HDR_AGE]++;
	} else if (!strncasecmp(t, "Content-MD5:", 12)) {
	    ReplyHeaderStats.misc[HDR_CONTENT_MD5]++;
	} else if (!strncasecmp(t, "ETag:", 5)) {
	    ReplyHeaderStats.misc[HDR_ETAG]++;
	} else if (!strncasecmp(t, "Max-Forwards:", 13)) {
	    ReplyHeaderStats.misc[HDR_MAX_FORWARDS]++;
	} else if (!strncasecmp(t, "Public:", 7)) {
	    ReplyHeaderStats.misc[HDR_PUBLIC]++;
	} else if (!strncasecmp(t, "Retry-After:", 12)) {
	    ReplyHeaderStats.misc[HDR_RETRY_AFTER]++;
	} else if (!strncasecmp(t, "Upgrade:", 8)) {
	    ReplyHeaderStats.misc[HDR_UPGRADE]++;
	} else if (!strncasecmp(t, "Warning:", 8)) {
	    ReplyHeaderStats.misc[HDR_WARNING]++;
	} else if (!strncasecmp(t, "Cache-Control:", 14)) {
	    for (t += 14; isspace(*t); t++);
	    if (!strncasecmp(t, "public", 6)) {
		EBIT_SET(reply->cache_control, SCC_PUBLIC);
		ReplyHeaderStats.cc[SCC_PUBLIC]++;
	    } else if (!strncasecmp(t, "private", 7)) {
		EBIT_SET(reply->cache_control, SCC_PRIVATE);
		ReplyHeaderStats.cc[SCC_PRIVATE]++;
	    } else if (!strncasecmp(t, "no-cache", 8)) {
		EBIT_SET(reply->cache_control, SCC_NOCACHE);
		ReplyHeaderStats.cc[SCC_NOCACHE]++;
	    } else if (!strncasecmp(t, "no-store", 8)) {
		EBIT_SET(reply->cache_control, SCC_NOSTORE);
		ReplyHeaderStats.cc[SCC_NOSTORE]++;
	    } else if (!strncasecmp(t, "no-transform", 12)) {
		EBIT_SET(reply->cache_control, SCC_NOTRANSFORM);
		ReplyHeaderStats.cc[SCC_NOTRANSFORM]++;
	    } else if (!strncasecmp(t, "must-revalidate", 15)) {
		EBIT_SET(reply->cache_control, SCC_MUSTREVALIDATE);
		ReplyHeaderStats.cc[SCC_MUSTREVALIDATE]++;
	    } else if (!strncasecmp(t, "proxy-revalidate", 16)) {
		EBIT_SET(reply->cache_control, SCC_PROXYREVALIDATE);
		ReplyHeaderStats.cc[SCC_PROXYREVALIDATE]++;
	    } else if (!strncasecmp(t, "max-age", 7)) {
		if ((t = strchr(t, '='))) {
		    delta = (time_t) atoi(++t);
		    reply->expires = squid_curtime + delta;
		    EBIT_SET(reply->cache_control, SCC_MAXAGE);
		    ReplyHeaderStats.cc[SCC_MAXAGE]++;
		}
	    }
	} else if (!strncasecmp(t, "Set-Cookie:", 11)) {
	    EBIT_SET(reply->misc_headers, HDR_SET_COOKIE);
	    ReplyHeaderStats.misc[HDR_SET_COOKIE]++;
	}
    }
    put_free_4k_page(headers);
    put_free_4k_page(line);
}

/* httpCheckPublic
 *
 *  Return 1 if the entry can be made public
 *         0 if the entry must be made private
 *        -1 if the entry should be negatively cached
 */
int
httpCheckPublic(struct _http_reply *reply, HttpStateData * httpState)
{
    request_t *request = httpState->request;
    switch (reply->code) {
	/* Responses that are cacheable */
    case 200:			/* OK */
    case 203:			/* Non-Authoritative Information */
    case 300:			/* Multiple Choices */
    case 301:			/* Moved Permanently */
    case 410:			/* Gone */
	/* don't cache objects from neighbors w/o LMT, Date, or Expires */
	if (EBIT_TEST(reply->cache_control, SCC_PRIVATE))
	    return 0;
	if (EBIT_TEST(reply->cache_control, SCC_NOCACHE))
	    return 0;
	if (BIT_TEST(request->flags, REQ_AUTH))
	    if (!EBIT_TEST(reply->cache_control, SCC_PROXYREVALIDATE))
		return 0;
	/*
	 * Dealing with cookies is quite a bit more complicated
	 * than this.  Ideally we should strip the cookie
	 * header from the reply but still cache the reply body.
	 * More confusion at draft-ietf-http-state-mgmt-05.txt.
	 */
	if (EBIT_TEST(reply->misc_headers, HDR_SET_COOKIE))
	    return 0;
	if (reply->date > -1)
	    return 1;
	if (reply->last_modified > -1)
	    return 1;
	if (!httpState->neighbor)
	    return 1;
	if (reply->expires > -1)
	    return 1;
#ifdef OLD_CODE
	if (entry->mem_obj->request->protocol != PROTO_HTTP)
	    /* XXX Remove this check after a while.  DW 8/21/96
	     * We won't keep some FTP objects from neighbors running
	     * 1.0.8 or earlier because their ftpget's don't 
	     * add a Date: field */
	    return 1;
#endif
	else
	    return 0;
	break;
	/* Responses that only are cacheable if the server says so */
    case 302:			/* Moved temporarily */
	if (reply->expires > -1)
	    return 1;
	else
	    return 0;
	break;
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
	break;
    }
    assert(0);
}

void
httpProcessReplyHeader(HttpStateData * httpState, const char *buf, int size)
{
    char *t = NULL;
    StoreEntry *entry = httpState->entry;
    int room;
    int hdr_len;
    struct _http_reply *reply = entry->mem_obj->reply;
    debug(11, 3) ("httpProcessReplyHeader: key '%s'\n", entry->key);
    if (httpState->reply_hdr == NULL)
	httpState->reply_hdr = get_free_8k_page();
    if (httpState->reply_hdr_state == 0) {
	hdr_len = strlen(httpState->reply_hdr);
	room = 8191 - hdr_len;
	strncat(httpState->reply_hdr, buf, room < size ? room : size);
	hdr_len += room < size ? room : size;
	if (hdr_len > 4 && strncmp(httpState->reply_hdr, "HTTP/", 5)) {
	    debug(11, 3) ("httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", entry->key);
	    httpState->reply_hdr_state += 2;
	    reply->code = 555;
	    return;
	}
	t = httpState->reply_hdr + hdr_len;
	/* headers can be incomplete only if object still arriving */
	if (!httpState->eof)
	    if ((t = mime_headers_end(httpState->reply_hdr)) == NULL)
		return;		/* headers not complete */
	*t = '\0';
	httpState->reply_hdr_state++;
    }
    if (httpState->reply_hdr_state == 1) {
	httpState->reply_hdr_state++;
	debug(11, 9) ("GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    httpState->reply_hdr);
	/* Parse headers into reply structure */
	httpParseReplyHeaders(httpState->reply_hdr, reply);
	storeTimestampsSet(entry);
	/* Check if object is cacheable or not based on reply code */
	debug(11, 3) ("httpProcessReplyHeader: HTTP CODE: %d\n", reply->code);
	switch (httpCheckPublic(reply, httpState)) {
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
	if (EBIT_TEST(reply->cache_control, SCC_PROXYREVALIDATE))
	    BIT_SET(entry->flag, ENTRY_REVALIDATE);
    }
}

static int
httpPconnTransferDone(HttpStateData * httpState)
{
    /* return 1 if we got the last of the data on a persistent connection */
    MemObject *mem = httpState->entry->mem_obj;
    struct _http_reply *reply = mem->reply;
    debug(11, 3) ("httpPconnTransferDone: FD %d\n", httpState->fd);
    if (!BIT_TEST(httpState->flags, HTTP_KEEPALIVE))
	return 0;
    debug(11, 5) ("httpPconnTransferDone: content_length=%d\n",
	reply->content_length);
    /*
     * !200 replies maybe don't have content-length, so
     * if we saw the end of the headers then try being persistent.
     */
    if (reply->code != 200)
	if (httpState->reply_hdr_state > 1)
	    return 1;
    /*
     * If there is no content-length, then we probably can't be persistent
     */
    if (reply->content_length == 0)
	return 0;
    /*
     * If there is a content_length, see if we've got all of it.  If so,
     * then we can recycle this connection.
     */
    debug(11, 5) ("httpPconnTransferDone: hdr_sz=%d\n", reply->hdr_sz);
    debug(11, 5) ("httpPconnTransferDone: inmem_hi=%d\n",
	mem->inmem_hi);
    if (mem->inmem_hi < reply->content_length + reply->hdr_sz)
	return 0;
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
    int off;
    ErrorState *err;
    if (protoAbortFetch(entry)) {
	storeAbort(entry, 0);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->inmem_hi;
    off = storeLowestMemReaderOffset(entry);
    if ((clen - off) > READ_AHEAD_GAP) {
	IOStats.Http.reads_deferred++;
	debug(11, 3) ("httpReadReply: Read deferred for Object: %s\n",
	    entry->url);
	debug(11, 3) ("                Current Gap: %d bytes\n", clen - off);
	/* reschedule, so it will be automatically reactivated
	 * when Gap is big enough. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    httpReadReply,
	    httpState, 0);
	/* disable read timeout until we are below the GAP */
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    commSetTimeout(fd, Config.Timeout.defer, NULL, NULL);
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, 1);
	return;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    errno = 0;
    len = read(fd, buf, SQUID_TCP_SO_RCVBUF);
    fd_bytes(fd, len, FD_READ);
    debug(11, 5) ("httpReadReply: FD %d: len %d.\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Http.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Http.read_hist[bin]++;
    }
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	} else {
	    if (clen == 0) {
		err = xcalloc(1, sizeof(ErrorState));
		err->type = ERR_READ_ERROR;
		err->errno = errno;
		err->http_status = HTTP_INTERNAL_SERVER_ERROR;
		err->request = requestLink(httpState->request);
		errorAppendEntry(entry, err);
	    }
	    storeAbort(entry, 0);
	    comm_close(fd);
	}
	debug(50, 2) ("httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
    } else if (len == 0 && entry->mem_obj->inmem_hi == 0) {
	if (fd_table[fd].uses > 1) {
	    httpRestart(httpState);
	} else {
	    httpState->eof = 1;
	    err = xcalloc(1, sizeof(ErrorState));
	    err->type = ERR_ZERO_SIZE_OBJECT;
	    err->errno = errno;
	    err->http_status = HTTP_SERVICE_UNAVAILABLE;
	    err->request = requestLink(httpState->request);
	    errorAppendEntry(entry, err);
	    storeAbort(entry, 0);
	    comm_close(fd);
	}
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	httpState->eof = 1;
	if (httpState->reply_hdr_state < 2)
	    httpProcessReplyHeader(httpState, buf, len);
	storeAppend(entry, buf, len);	/* invoke handlers! */
	storeComplete(entry);	/* deallocates mem_obj->request */
	comm_close(fd);
    } else {
	if (httpState->reply_hdr_state < 2)
	    httpProcessReplyHeader(httpState, buf, len);
	storeAppend(entry, buf, len);
	if (httpPconnTransferDone(httpState)) {
	    pconnPush(fd, request->host, request->port);
	    comm_remove_close_handler(fd, httpStateFree, httpState);
	    storeComplete(entry);	/* deallocates mem_obj->request */
	    httpState->fd = -1;
	    httpStateFree(-1, httpState);
	} else {
	    commSetSelect(fd, COMM_SELECT_READ, httpReadReply, httpState, 0);
	}
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
httpSendComplete(int fd, char *buf, int size, int errflag, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);
    if (errflag) {
	err = xcalloc(1, sizeof(ErrorState));
	err->type = ERR_WRITE_ERROR;
	err->http_status = HTTP_INTERNAL_SERVER_ERROR;
	err->errno = errno;
	err->request = requestLink(httpState->request);
	errorAppendEntry(entry, err);
	storeAbort(entry, 0);
	comm_close(fd);
	return;
    } else {
	/* Schedule read reply. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    httpReadReply,
	    httpState, 0);
    }
}

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

size_t
httpBuildRequestHeader(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    size_t * in_len,
    char *hdr_out,
    size_t out_sz,
    int cfd,
    int flags)
{
    LOCAL_ARRAY(char, ybuf, MAX_URL + 32);
    char *xbuf = get_free_4k_page();
    char *viabuf = get_free_4k_page();
    char *fwdbuf = get_free_4k_page();
    char *t = NULL;
    char *s = NULL;
    char *end = NULL;
    size_t len = 0;
    size_t hdr_len = 0;
    size_t l;
    int hdr_flags = 0;
    int cc_flags = 0;
    int n;
    const char *url = NULL;
    char *hdr_in = orig_request->headers;

    assert(hdr_in != NULL);
    debug(11, 3) ("httpBuildRequestHeader: INPUT:\n%s\n", hdr_in);
    xstrncpy(fwdbuf, "X-Forwarded-For: ", 4096);
    xstrncpy(viabuf, "Via: ", 4096);
    snprintf(ybuf, MAX_URL + 32, "%s %s HTTP/1.0",
	RequestMethodStr[request->method],
	*request->urlpath ? request->urlpath : "/");
    httpAppendRequestHeader(hdr_out, ybuf, &len, out_sz, 1);
    /* Add IMS header */
    if (entry && entry->lastmod && request->method == METHOD_GET) {
	snprintf(ybuf, MAX_URL + 32, "If-Modified-Since: %s", mkrfc1123(entry->lastmod));
	httpAppendRequestHeader(hdr_out, ybuf, &len, out_sz, 1);
	EBIT_SET(hdr_flags, HDR_IMS);
    }
    end = mime_headers_end(hdr_in);
    for (t = hdr_in; t < end; t += strcspn(t, crlf), t += strspn(t, crlf)) {
	hdr_len = t - hdr_in;
	l = strcspn(t, crlf) + 1;
	if (l > 4096)
	    l = 4096;
	xstrncpy(xbuf, t, l);
	debug(11, 5) ("httpBuildRequestHeader: %s\n", xbuf);
	if (strncasecmp(xbuf, "Proxy-Connection:", 17) == 0)
	    continue;
	if (strncasecmp(xbuf, "Proxy-authorization:", 20) == 0)
	    /* If we're not going to do proxy auth, then it must be passed on */
	    if (BIT_TEST(request->flags, REQ_USED_PROXY_AUTH))
		continue;
	if (strncasecmp(xbuf, "Connection:", 11) == 0)
	    continue;
	if (strncasecmp(xbuf, "Host:", 5) == 0) {
	    EBIT_SET(hdr_flags, HDR_HOST);
	} else if (strncasecmp(xbuf, "Cache-Control:", 14) == 0) {
	    for (s = xbuf + 14; *s && isspace(*s); s++);
	    if (strncasecmp(s, "Max-age=", 8) == 0)
		EBIT_SET(cc_flags, CCC_MAXAGE);
	} else if (strncasecmp(xbuf, "Via:", 4) == 0) {
	    for (s = xbuf + 4; *s && isspace(*s); s++);
	    if (strlen(viabuf) + strlen(s) < 4000)
		strcat(viabuf, s);
	    strcat(viabuf, ", ");
	    continue;
	} else if (strncasecmp(xbuf, "X-Forwarded-For:", 16) == 0) {
	    for (s = xbuf + 16; *s && isspace(*s); s++);
	    if (strlen(fwdbuf) + strlen(s) < 4000)
		strcat(fwdbuf, s);
	    strcat(fwdbuf, ", ");
	    continue;
	} else if (strncasecmp(xbuf, "If-Modified-Since:", 18) == 0) {
	    if (EBIT_TEST(hdr_flags, HDR_IMS))
		continue;
	} else if (strncasecmp(xbuf, "Max-Forwards:", 13) == 0) {
	    if (orig_request->method == METHOD_TRACE) {
		for (s = xbuf + 13; *s && isspace(*s); s++);
		n = atoi(s);
		snprintf(xbuf, 4096, "Max-Forwards: %d", n - 1);
	    }
	}
	httpAppendRequestHeader(hdr_out, xbuf, &len, out_sz - 512, 1);
    }
    hdr_len = t - hdr_in;
    if (Config.fake_ua && strstr(hdr_out, "User-Agent") == NULL) {
	snprintf(ybuf, MAX_URL + 32, "User-Agent: %s", Config.fake_ua);
	httpAppendRequestHeader(hdr_out, ybuf, &len, out_sz, 0);
    }
    /* Append Via: */
    /* snprintf would fail here too */
    snprintf(ybuf, MAX_URL + 32, "%3.1f %s", orig_request->http_ver, ThisCache);
    strcat(viabuf, ybuf);
    httpAppendRequestHeader(hdr_out, viabuf, &len, out_sz, 1);
    /* Append to X-Forwarded-For: */
    strcat(fwdbuf, cfd < 0 ? "unknown" : fd_table[cfd].ipaddr);
    httpAppendRequestHeader(hdr_out, fwdbuf, &len, out_sz, 1);
    if (!EBIT_TEST(hdr_flags, HDR_HOST)) {
	snprintf(ybuf, MAX_URL + 32, "Host: %s", orig_request->host);
	httpAppendRequestHeader(hdr_out, ybuf, &len, out_sz, 1);
    }
    if (!EBIT_TEST(cc_flags, CCC_MAXAGE)) {
	url = entry ? entry->url : urlCanonical(orig_request, NULL);
	snprintf(ybuf, MAX_URL + 32, "Cache-control: Max-age=%d", (int) getMaxAge(url));
	httpAppendRequestHeader(hdr_out, ybuf, &len, out_sz, 1);
	if (request->urlpath) {
	    assert(strstr(url, request->urlpath));
	}
    }
    /* maybe append Connection: Keep-Alive */
    if (BIT_TEST(flags, HTTP_KEEPALIVE)) {
	if (BIT_TEST(flags, HTTP_PROXYING)) {
	    snprintf(ybuf, MAX_URL + 32, "Proxy-Connection: Keep-Alive");
	} else {
	    snprintf(ybuf, MAX_URL + 32, "Connection: Keep-Alive");
	}
	httpAppendRequestHeader(hdr_out, ybuf, &len, out_sz, 1);
    }
    httpAppendRequestHeader(hdr_out, null_string, &len, out_sz, 1);
    put_free_4k_page(xbuf);
    put_free_4k_page(viabuf);
    put_free_4k_page(fwdbuf);
    if (in_len)
	*in_len = hdr_len;
    if ((l = strlen(hdr_out)) != len) {
	debug_trap("httpBuildRequestHeader: size mismatch");
	len = l;
    }
    debug(11, 3) ("httpBuildRequestHeader: OUTPUT:\n%s\n", hdr_out);
    return len;
}

/* This will be called when connect completes. Write request. */
static void
httpSendRequest(int fd, void *data)
{
    HttpStateData *httpState = data;
    char *buf = NULL;
    int len = 0;
    int buflen;
    request_t *req = httpState->request;
    int buftype = 0;
    StoreEntry *entry = httpState->entry;
    int cfd;

    debug(11, 5) ("httpSendRequest: FD %d: httpState %p.\n", fd, httpState);
    buflen = strlen(req->urlpath);
    if (req->headers)
	buflen += req->headers_sz + 1;
    buflen += 512;		/* lots of extra */

    if ((req->method == METHOD_POST || req->method == METHOD_PUT)) {
	debug_trap("httpSendRequest: should not be handling POST/PUT request");
	return;
    }
    if (buflen < DISK_PAGE_SIZE) {
	buf = get_free_8k_page();
	buftype = BUF_TYPE_8K;
	buflen = DISK_PAGE_SIZE;
    } else {
	buf = xcalloc(buflen, 1);
	buftype = BUF_TYPE_MALLOC;
    }
    if (!opt_forwarded_for)
	cfd = -1;
    else if (entry->mem_obj == NULL)
	cfd = -1;
    else
	cfd = entry->mem_obj->fd;
    if (httpState->neighbor != NULL)
	BIT_SET(httpState->flags, HTTP_PROXYING);
    if (req->method == METHOD_GET)
	BIT_SET(httpState->flags, HTTP_KEEPALIVE);
    len = httpBuildRequestHeader(req,
	httpState->orig_request ? httpState->orig_request : req,
	entry,
	NULL,
	buf,
	buflen,
	cfd,
	httpState->flags);
    debug(11, 6) ("httpSendRequest: FD %d:\n%s\n", fd, buf);
    comm_write(fd,
	buf,
	len,
	httpSendComplete,
	httpState,
	buftype == BUF_TYPE_8K ? put_free_8k_page : xfree);
#ifdef BREAKS_PCONN_RESTART
    requestUnlink(httpState->orig_request);
    httpState->orig_request = NULL;
#endif
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
	entry->url);
    if (fd < 0) {
	debug(11, 4) ("httpSocketOpen: Failed because we're out of sockets.\n");
	err = xcalloc(1, sizeof(ErrorState));
	err->type = ERR_SOCKET_FAILURE;
	err->http_status = HTTP_INTERNAL_SERVER_ERROR;
	err->errno = errno;
	if (request)
	    err->request = requestLink(request);
	errorAppendEntry(entry, err);
	storeAbort(entry, 0);
    }
    return fd;
}

static HttpStateData *
httpBuildState(int fd, StoreEntry * entry, request_t * orig_request, peer * e)
{
    HttpStateData *httpState = xcalloc(1, sizeof(HttpStateData));
    request_t *request;
    storeLockObject(entry);
    cbdataAdd(httpState);
    httpState->entry = entry;
    httpState->fd = fd;
    if (e) {
	request = get_free_request_t();
	request->method = orig_request->method;
	xstrncpy(request->host, e->host, SQUIDHOSTNAMELEN);
	request->port = e->http_port;
	xstrncpy(request->urlpath, entry->url, MAX_URL);
	httpState->request = requestLink(request);
	httpState->neighbor = e;
	httpState->orig_request = requestLink(orig_request);
	BIT_SET(request->flags, REQ_PROXYING);
    } else {
	httpState->request = requestLink(orig_request);
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
	RequestMethodStr[request->method], entry->url);
    if (e) {
	if (e->options & NEIGHBOR_PROXY_ONLY)
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
    if ((fd = httpSocketOpen(entry, NULL)) < 0)
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

static void
httpRestart(HttpStateData * httpState)
{
    /* restart a botched request from a persistent connection */
    debug(11, 1) ("Retrying HTTP request for %s\n", httpState->entry->url);
    if (httpState->fd >= 0) {
	comm_remove_close_handler(httpState->fd, httpStateFree, httpState);
	comm_close(httpState->fd);
	httpState->fd = -1;
    }
    httpState->fd = httpSocketOpen(httpState->entry, httpState->request);
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
	err = xcalloc(1, sizeof(ErrorState));
	err->type = ERR_DNS_FAIL;
	err->http_status = HTTP_SERVICE_UNAVAILABLE;
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->request = requestLink(request);
	errorAppendEntry(entry, err);
	storeAbort(entry, 0);
	comm_close(fd);
    } else if (status != COMM_OK) {
	err = xcalloc(1, sizeof(ErrorState));
	err->type = ERR_CONNECT_FAIL;
	err->http_status = HTTP_SERVICE_UNAVAILABLE;
	err->errno = errno;
	err->host = xstrdup(request->host);
	err->port = request->port;
	err->request = requestLink(request);
	errorAppendEntry(entry, err);
	storeAbort(entry, 0);
	if (httpState->neighbor)
	    peerCheckConnectStart(httpState->neighbor);
	comm_close(fd);
    } else {
	fd_note(fd, entry->url);
	fd_table[fd].uses++;
	commSetSelect(fd, COMM_SELECT_WRITE, httpSendRequest, httpState, 0);
    }
}

void
httpReplyHeaderStats(StoreEntry * entry)
{
    http_server_cc_t i;
    http_hdr_misc_t j;
    storeAppendPrintf(entry, open_bracket);
    storeAppendPrintf(entry, "{HTTP Reply Headers:}\n");
    storeAppendPrintf(entry, "{       Headers parsed: %d}\n",
	ReplyHeaderStats.parsed);
    for (j = HDR_AGE; j < HDR_MISC_END; j++)
	storeAppendPrintf(entry, "{%21.21s: %d}\n",
	    HttpHdrMiscStr[j],
	    ReplyHeaderStats.misc[j]);
    for (i = SCC_PUBLIC; i < SCC_ENUM_END; i++)
	storeAppendPrintf(entry, "{Cache-Control %s: %d}\n",
	    HttpServerCCStr[i],
	    ReplyHeaderStats.cc[i]);
    storeAppendPrintf(entry, close_bracket);
}

static void
httpAbort(void *data)
{
    HttpStateData *httpState = data;
    debug(11, 1) ("httpAbort: %s\n", httpState->entry->url);
    comm_close(httpState->fd);
}

static char *
httpStatusString(int status)
{
    char *p = NULL;
    switch (status) {
    case 100:
	p = "Continue";
	break;
    case 101:
	p = "Switching Protocols";
	break;
    case 200:
	p = "OK";
	break;
    case 201:
	p = "Created";
	break;
    case 202:
	p = "Accepted";
	break;
    case 203:
	p = "Non-Authoritative Information";
	break;
    case 204:
	p = "No Content";
	break;
    case 205:
	p = "Reset Content";
	break;
    case 206:
	p = "Partial Content";
	break;
    case 300:
	p = "Multiple Choices";
	break;
    case 301:
	p = "Moved Permanently";
	break;
    case 302:
	p = "Moved Temporarily";
	break;
    case 303:
	p = "See Other";
	break;
    case 304:
	p = "Not Modified";
	break;
    case 305:
	p = "Use Proxy";
	break;
    case 400:
	p = "Bad Request";
	break;
    case 401:
	p = "Unauthorized";
	break;
    case 402:
	p = "Payment Required";
	break;
    case 403:
	p = "Forbidden";
	break;
    case 404:
	p = "Not Found";
	break;
    case 405:
	p = "Method Not Allowed";
	break;
    case 406:
	p = "Not Acceptable";
	break;
    case 407:
	p = "Proxy Authentication Required";
	break;
    case 408:
	p = "Request Time-out";
	break;
    case 409:
	p = "Conflict";
	break;
    case 410:
	p = "Gone";
	break;
    case 411:
	p = "Length Required";
	break;
    case 412:
	p = "Precondition Failed";
	break;
    case 413:
	p = "Request Entity Too Large";
	break;
    case 414:
	p = "Request-URI Too Large";
	break;
    case 415:
	p = "Unsupported Media Type";
	break;
    case 500:
	p = "Internal Server Error";
	break;
    case 501:
	p = "Not Implemented";
	break;
    case 502:
	p = "Bad Gateway";
	break;
    case 503:
	p = "Service Unavailable";
	break;
    case 504:
	p = "Gateway Time-out";
	break;
    case 505:
	p = "HTTP Version not supported";
	break;
    default:
	p = "Unknown";
	debug(11, 0) ("Unknown HTTP status code: %d\n", status);
	break;
    }
    return p;
}

char *
httpReplyHeader(double ver,
    http_status status,
    char *ctype,
    int clen,
    time_t lmt,
    time_t expires)
{
    LOCAL_ARRAY(char, buf, HTTP_REPLY_BUF_SZ);
    LOCAL_ARRAY(char, float_buf, 64);
    int l = 0;
    int s = HTTP_REPLY_BUF_SZ;
    /* argh, ../lib/snprintf.c doesn't support '%f' */
    snprintf(float_buf, 64, "%3.1f", ver);
    assert(strlen(float_buf) == 3);
    l += snprintf(buf + l, s - l, "HTTP/%s %d %s\r\n",
	float_buf,
	(int) status,
	httpStatusString(status));
    l += snprintf(buf + l, s - l, "Server: Squid/%s\r\n", SQUID_VERSION);
    l += snprintf(buf + l, s - l, "Date: %s\r\n", mkrfc1123(squid_curtime));
    if (expires >= 0)
	l += snprintf(buf + l, s - l, "Expires: %s\r\n", mkrfc1123(expires));
    if (lmt)
	l += snprintf(buf + l, s - l, "Last-Modified: %s\r\n", mkrfc1123(lmt));
    if (clen > 0)
	l += snprintf(buf + l, s - l, "Content-Length: %d\r\n", clen);
    if (ctype)
	l += snprintf(buf + l, s - l, "Content-Type: %s\r\n", ctype);
    return buf;
}
