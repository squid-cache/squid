/*
 * $Id: http.cc,v 1.99 1996/11/07 18:53:15 wessels Exp $
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

#include "squid.h"

#define HTTP_DELETE_GAP   (1<<18)

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

typedef enum {
    CCC_NOCACHE,
    CCC_NOSTORE,
    CCC_MAXAGE,
    CCC_MAXSTALE,
    CCC_MINFRESH,
    CCC_ONLYIFCACHED,
    CCC_ENUM_END
} http_client_cc_t;

char *HttpServerCCStr[] =
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

static struct {
    int parsed;
    int date;
    int lm;
    int exp;
    int clen;
    int ctype;
    int cc[SCC_ENUM_END];
} ReplyHeaderStats;

static void httpStateFree _PARAMS((int fd, void *));
static void httpReadReplyTimeout _PARAMS((int fd, void *));
static void httpLifetimeExpire _PARAMS((int fd, void *));
static void httpMakePublic _PARAMS((StoreEntry *));
static void httpMakePrivate _PARAMS((StoreEntry *));
static void httpCacheNegatively _PARAMS((StoreEntry *));
static void httpReadReply _PARAMS((int fd, void *));
static void httpSendComplete _PARAMS((int fd, char *, int, int, void *));
static void httpSendRequest _PARAMS((int fd, void *));
static void httpConnect _PARAMS((int fd, const ipcache_addrs *, void *));
static void httpConnectDone _PARAMS((int fd, int status, void *data));

static void
httpStateFree(int fd, void *data)
{
    HttpStateData *httpState = data;
    if (httpState == NULL)
	return;
    storeUnlockObject(httpState->entry);
    if (httpState->reply_hdr) {
	put_free_8k_page(httpState->reply_hdr);
	httpState->reply_hdr = NULL;
    }
    requestUnlink(httpState->request);
    xfree(httpState);
}

int
httpCachable(const char *url, int method)
{
    /* GET and HEAD are cachable. Others are not. */
    if (method != METHOD_GET && method != METHOD_HEAD)
	return 0;
    /* else cachable */
    return 1;
}

/* This will be called when timeout on read. */
static void
httpReadReplyTimeout(int fd, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = NULL;
    entry = httpState->entry;
    debug(11, 4, "httpReadReplyTimeout: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
    comm_close(fd);
}

/* This will be called when socket lifetime is expired. */
static void
httpLifetimeExpire(int fd, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = httpState->entry;
    debug(11, 4, "httpLifeTimeExpire: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    commSetSelect(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, NULL, NULL, 0);
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
    storeSetPrivateKey(entry);
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
httpParseHeaders(const char *buf, struct _http_reply *reply)
{
    char *headers = NULL;
    char *t = NULL;
    char *s = NULL;
    int delta;

    ReplyHeaderStats.parsed++;
    headers = xstrdup(buf);
    t = strtok(headers, "\n");
    while (t) {
	s = t + strlen(t);
	while (*s == '\r')
	    *s-- = '\0';
	if (!strncasecmp(t, "HTTP", 4)) {
	    sscanf(t + 1, "%lf", &reply->version);
	    if ((t = strchr(t, ' '))) {
		t++;
		reply->code = atoi(t);
	    }
	} else if (!strncasecmp(t, "Content-type:", 13)) {
	    if ((t = strchr(t, ' '))) {
		t++;
		strncpy(reply->content_type, t, HTTP_REPLY_FIELD_SZ - 1);
		ReplyHeaderStats.ctype++;
	    }
	} else if (!strncasecmp(t, "Content-length:", 15)) {
	    if ((t = strchr(t, ' '))) {
		t++;
		reply->content_length = atoi(t);
		ReplyHeaderStats.clen++;
	    }
	} else if (!strncasecmp(t, "Date:", 5)) {
	    if ((t = strchr(t, ' '))) {
		t++;
		strncpy(reply->date, t, HTTP_REPLY_FIELD_SZ - 1);
		ReplyHeaderStats.date++;
	    }
	} else if (!strncasecmp(t, "Expires:", 8)) {
	    if ((t = strchr(t, ' '))) {
		t++;
		strncpy(reply->expires, t, HTTP_REPLY_FIELD_SZ - 1);
		ReplyHeaderStats.exp++;
	    }
	} else if (!strncasecmp(t, "Last-Modified:", 14)) {
	    if ((t = strchr(t, ' '))) {
		t++;
		strncpy(reply->last_modified, t, HTTP_REPLY_FIELD_SZ - 1);
		ReplyHeaderStats.lm++;
	    }
	} else if (!strncasecmp(t, "Cache-Control:", 14)) {
	    if ((t = strtok(NULL, w_space))) {
		if (!strncasecmp(t, "public", 6)) {
		    EBIT_SET(reply->cache_control, SCC_PUBLIC);
		    ReplyHeaderStats.cc[SCC_PUBLIC]++;
		} else if (!strncasecmp(t, "private", 7)) {
		    EBIT_SET(reply->cache_control, SCC_PRIVATE);
		    ReplyHeaderStats.cc[SCC_PRIVATE]++;
		} else if (!strncasecmp(t, "no-cache", 8)) {
		    EBIT_SET(reply->cache_control, SCC_NOCACHE);
		    ReplyHeaderStats.cc[SCC_NOCACHE]++;
		} else if (!strncasecmp(t, "max-age", 7)) {
		    if ((t = strchr(t, '='))) {
			delta = atoi(++t);
			EBIT_SET(reply->cache_control, SCC_MAXAGE);
			ReplyHeaderStats.cc[SCC_MAXAGE]++;
			strcpy(reply->expires, mkrfc1123(squid_curtime + delta));
		    }
		}
	    }
	}
	t = strtok(NULL, "\n");
    }
#if LOG_TIMESTAMPS
    fprintf(timestamp_log, "T %9d D %9d L %9d E %9d\n",
	squid_curtime,
	parse_rfc1123(reply->date),
	parse_rfc1123(reply->last_modified),
	parse_rfc1123(reply->expires));
#endif /* LOG_TIMESTAMPS */
    safe_free(headers);
}


void
httpProcessReplyHeader(HttpStateData * httpState, const char *buf, int size)
{
    char *t = NULL;
    StoreEntry *entry = httpState->entry;
    int room;
    int hdr_len;
    struct _http_reply *reply = NULL;

    debug(11, 3, "httpProcessReplyHeader: key '%s'\n", entry->key);

    if (httpState->reply_hdr == NULL) {
	httpState->reply_hdr = get_free_8k_page();
	memset(httpState->reply_hdr, '\0', 8192);
    }
    if (httpState->reply_hdr_state == 0) {
	hdr_len = strlen(httpState->reply_hdr);
	room = 8191 - hdr_len;
	strncat(httpState->reply_hdr, buf, room < size ? room : size);
	hdr_len += room < size ? room : size;
	if (hdr_len > 4 && strncmp(httpState->reply_hdr, "HTTP/", 5)) {
	    debug(11, 3, "httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", entry->key);
	    httpState->reply_hdr_state += 2;
	    entry->mem_obj->reply->code = 555;
	    return;
	}
	t = httpState->reply_hdr + hdr_len;
	/* headers can be incomplete only if object still arriving */
	if (!httpState->eof)
	    if ((t = mime_headers_end(httpState->reply_hdr)) == NULL)
		return;		/* headers not complete */
	*t = '\0';
	reply = entry->mem_obj->reply;
	reply->hdr_sz = t - httpState->reply_hdr;
	debug(11, 7, "httpProcessReplyHeader: hdr_sz = %d\n", reply->hdr_sz);
	httpState->reply_hdr_state++;
    }
    if (httpState->reply_hdr_state == 1) {
	httpState->reply_hdr_state++;
	debug(11, 9, "GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
	    httpState->reply_hdr);
	/* Parse headers into reply structure */
	httpParseHeaders(httpState->reply_hdr, reply);
	timestampsSet(entry);
	/* Check if object is cacheable or not based on reply code */
	if (reply->code)
	    debug(11, 3, "httpProcessReplyHeader: HTTP CODE: %d\n", reply->code);
	switch (reply->code) {
	    /* Responses that are cacheable */
	case 200:		/* OK */
	case 203:		/* Non-Authoritative Information */
	case 300:		/* Multiple Choices */
	case 301:		/* Moved Permanently */
	case 410:		/* Gone */
	    /* don't cache objects from neighbors w/o LMT, Date, or Expires */
	    if (EBIT_TEST(reply->cache_control, SCC_PRIVATE))
		httpMakePrivate(entry);
	    else if (EBIT_TEST(reply->cache_control, SCC_NOCACHE))
		httpMakePrivate(entry);
	    else if (*reply->date)
		httpMakePublic(entry);
	    else if (*reply->last_modified)
		httpMakePublic(entry);
	    else if (!httpState->neighbor)
		httpMakePublic(entry);
	    else if (*reply->expires)
		httpMakePublic(entry);
	    else if (entry->mem_obj->request->protocol != PROTO_HTTP)
		/* XXX Remove this check after a while.  DW 8/21/96
		 * We won't keep some FTP objects from neighbors running
		 * 1.0.8 or earlier because their ftpget's don't 
		 * add a Date: field */
		httpMakePublic(entry);
	    else
		httpMakePrivate(entry);
	    break;
	    /* Responses that only are cacheable if the server says so */
	case 302:		/* Moved temporarily */
	    if (*reply->expires)
		httpMakePublic(entry);
	    else
		httpMakePrivate(entry);
	    break;
	    /* Errors can be negatively cached */
	case 204:		/* No Content */
	case 305:		/* Use Proxy (proxy redirect) */
	case 400:		/* Bad Request */
	case 403:		/* Forbidden */
	case 404:		/* Not Found */
	case 405:		/* Method Now Allowed */
	case 414:		/* Request-URI Too Long */
	case 500:		/* Internal Server Error */
	case 501:		/* Not Implemented */
	case 502:		/* Bad Gateway */
	case 503:		/* Service Unavailable */
	case 504:		/* Gateway Timeout */
	    httpCacheNegatively(entry);
	    break;
	    /* Some responses can never be cached */
	case 303:		/* See Other */
	case 304:		/* Not Modified */
	case 401:		/* Unauthorized */
	case 407:		/* Proxy Authentication Required */
	default:		/* Unknown status code */
	    httpMakePrivate(entry);
	    break;
	}
    }
}


/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
/* XXX this function is too long! */
static void
httpReadReply(int fd, void *data)
{
    HttpStateData *httpState = data;
    LOCAL_ARRAY(char, buf, SQUID_TCP_SO_RCVBUF);
    int len;
    int bin;
    int clen;
    int off;
    StoreEntry *entry = NULL;

    entry = httpState->entry;
    if (entry->flag & DELETE_BEHIND && !storeClientWaiting(entry)) {
	/* we can terminate connection right now */
	squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->e_current_len;
    off = storeGetLowestReaderOffset(entry);
    if ((clen - off) > HTTP_DELETE_GAP) {
	if (entry->flag & CLIENT_ABORT_REQUEST) {
	    squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	    comm_close(fd);
	    return;
	}
	IOStats.Http.reads_deferred++;
	debug(11, 3, "httpReadReply: Read deferred for Object: %s\n",
	    entry->url);
	debug(11, 3, "                Current Gap: %d bytes\n", clen - off);
	/* reschedule, so it will be automatically reactivated
	 * when Gap is big enough. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    httpReadReply,
	    (void *) httpState, 0);
	/* disable read timeout until we are below the GAP */
	commSetSelect(fd,
	    COMM_SELECT_TIMEOUT,
	    NULL,
	    (void *) NULL,
	    (time_t) 0);
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    comm_set_fd_lifetime(fd, 3600);	/* limit during deferring */
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, Config.stallDelay);
	return;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    errno = 0;
    len = read(fd, buf, SQUID_TCP_SO_RCVBUF);
    debug(11, 5, "httpReadReply: FD %d: len %d.\n", fd, len);
    comm_set_fd_lifetime(fd, 86400);	/* extend after good read */
    if (len > 0) {
	IOStats.Http.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Http.read_hist[bin]++;
    }
    if (len < 0) {
	debug(11, 2, "httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(fd, COMM_SELECT_READ,
		httpReadReply, (void *) httpState, 0);
	    commSetSelect(fd, COMM_SELECT_TIMEOUT,
		httpReadReplyTimeout, (void *) httpState, Config.readTimeout);
	} else {
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	httpState->eof = 1;
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	httpState->eof = 1;
	if (httpState->reply_hdr_state < 2)
	    httpProcessReplyHeader(httpState, buf, len);
	storeAppend(entry, buf, len);	/* invoke handlers! */
	storeComplete(entry);	/* deallocates mem_obj->request */
	comm_close(fd);
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	comm_close(fd);
    } else {
	if (httpState->reply_hdr_state < 2)
	    httpProcessReplyHeader(httpState, buf, len);
	storeAppend(entry, buf, len);
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    httpReadReply,
	    (void *) httpState, 0);
	commSetSelect(fd,
	    COMM_SELECT_TIMEOUT,
	    httpReadReplyTimeout,
	    (void *) httpState,
	    Config.readTimeout);
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
httpSendComplete(int fd, char *buf, int size, int errflag, void *data)
{
    HttpStateData *httpState = data;
    StoreEntry *entry = NULL;

    entry = httpState->entry;
    debug(11, 5, "httpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);

    if (errflag) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    } else {
	/* Schedule read reply. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    httpReadReply,
	    (void *) httpState, 0);
	commSetSelect(fd,
	    COMM_SELECT_TIMEOUT,
	    httpReadReplyTimeout,
	    (void *) httpState,
	    Config.readTimeout);
	comm_set_fd_lifetime(fd, 86400);	/* extend lifetime */
    }
}

/* This will be called when connect completes. Write request. */
static void
httpSendRequest(int fd, void *data)
{
    HttpStateData *httpState = data;
    char *xbuf = NULL;
    char *ybuf = NULL;
    char *buf = NULL;
    char *t = NULL;
    char *post_buf = NULL;
    int post_buf_sz = 0;
    const char *const crlf = "\r\n";
    int len = 0;
    int buflen;
    int cfd = -1;
    request_t *req = httpState->request;
    const char *Method = RequestMethodStr[req->method];
    int buftype = 0;
    StoreEntry *entry = httpState->entry;
    int saw_host = 0;
    int did_ims = 0;

    debug(11, 5, "httpSendRequest: FD %d: httpState %p.\n", fd, httpState);
    buflen = strlen(Method) + strlen(req->urlpath);
    if (httpState->req_hdr)
	buflen += httpState->req_hdr_sz + 1;
    buflen += 512;		/* lots of extra */

    if ((req->method == METHOD_POST || req->method == METHOD_PUT) && httpState->req_hdr) {
	if ((t = mime_headers_end(httpState->req_hdr))) {
	    post_buf_sz = httpState->req_hdr_sz - (t - httpState->req_hdr);
	    post_buf = xmalloc(post_buf_sz + 1);
	    xmemcpy(post_buf, t, post_buf_sz);
	    *(post_buf + post_buf_sz) = '\0';
	    *t = '\0';
	}
    }
    if (buflen < DISK_PAGE_SIZE) {
	buf = get_free_8k_page();
	memset(buf, '\0', buflen);
	buftype = BUF_TYPE_8K;
    } else {
	buf = xcalloc(buflen, 1);
	buftype = BUF_TYPE_MALLOC;
    }

    sprintf(buf, "%s %s HTTP/1.0\r\n",
	Method,
	*req->urlpath ? req->urlpath : "/");
    len = strlen(buf);
    /* Add IMS header */
    if (entry->lastmod && req->method == METHOD_GET) {
	debug(11, 3, "httpSendRequest: Adding IMS: %s\r\n",
	    mkrfc1123(entry->lastmod));
	ybuf = get_free_4k_page();
	sprintf(ybuf, "If-Modified-Since: %s\r\n", mkrfc1123(entry->lastmod));
	strcat(buf, ybuf);
	len += strlen(ybuf);
	put_free_4k_page(ybuf);
	did_ims = 1;
    }
    if (httpState->req_hdr) {	/* we have to parse the request header */
	xbuf = xstrdup(httpState->req_hdr);
	for (t = strtok(xbuf, crlf); t; t = strtok(NULL, crlf)) {
	    if (strncasecmp(t, "Connection:", 11) == 0)
		continue;
	    if (strncasecmp(t, "Host:", 5) == 0)
		saw_host = 1;
	    if (did_ims && !strncasecmp(t, "If-Modified-Since:", 18))
		continue;
	    if (len + (int) strlen(t) > buflen - 10)
		continue;
	    strcat(buf, t);
	    strcat(buf, crlf);
	    len += strlen(t) + 2;
	}
	xfree(xbuf);
    }
    /* Add Forwarded: header */
    ybuf = get_free_4k_page();
    if (entry->mem_obj)
	cfd = entry->mem_obj->fd_of_first_client;
    if (cfd > -1 && opt_forwarded_for) {
	sprintf(ybuf, "%s for %s\r\n", ForwardedBy, fd_table[cfd].ipaddr);
    } else {
	sprintf(ybuf, "%s\r\n", ForwardedBy);
    }
    strcat(buf, ybuf);
    len += strlen(ybuf);
    put_free_4k_page(ybuf);
    ybuf = NULL;

    /* Add Host: header */
    if (!saw_host) {
	ybuf = get_free_4k_page();
	sprintf(ybuf, "Host: %s\r\n", req->host);
	strcat(buf, ybuf);
	len += strlen(ybuf);
	put_free_4k_page(ybuf);
    }
    strcat(buf, crlf);
    len += 2;
    if (post_buf) {
	xmemcpy(buf + len, post_buf, post_buf_sz);
	len += post_buf_sz;
	xfree(post_buf);
    }
    debug(11, 6, "httpSendRequest: FD %d:\n%s\n", fd, buf);
    comm_write(fd,
	buf,
	len,
	30,
	httpSendComplete,
	httpState,
	buftype == BUF_TYPE_8K ? put_free_8k_page : xfree);
}

int
proxyhttpStart(edge * e, const char *url, StoreEntry * entry)
{
    int sock;
    HttpStateData *httpState = NULL;
    request_t *request = NULL;

    debug(11, 3, "proxyhttpStart: \"%s %s\"\n",
	RequestMethodStr[entry->method], url);
    debug(11, 10, "proxyhttpStart: HTTP request header:\n%s\n",
	entry->mem_obj->mime_hdr);

    if (e->options & NEIGHBOR_PROXY_ONLY)
	storeStartDeleteBehind(entry);

    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(11, 4, "proxyhttpStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    httpState = xcalloc(1, sizeof(HttpStateData));
    storeLockObject(httpState->entry = entry, NULL, NULL);
    httpState->req_hdr = entry->mem_obj->mime_hdr;
    httpState->req_hdr_sz = entry->mem_obj->mime_hdr_sz;
    request = get_free_request_t();
    httpState->request = requestLink(request);
    httpState->neighbor = e;
    /* register the handler to free HTTP state data when the FD closes */
    comm_add_close_handler(sock,
	httpStateFree,
	(void *) httpState);
    request->method = entry->method;
    strncpy(request->host, e->host, SQUIDHOSTNAMELEN);
    request->port = e->http_port;
    strncpy(request->urlpath, url, MAX_URL);
    ipcache_nbgethostbyname(request->host,
	sock,
	httpConnect,
	httpState);
    return COMM_OK;
}

static void
httpConnect(int fd, const ipcache_addrs * ia, void *data)
{
    HttpStateData *httpState = data;
    request_t *request = httpState->request;
    StoreEntry *entry = httpState->entry;
    if (ia == NULL) {
	debug(11, 4, "httpConnect: Unknown host: %s\n", request->host);
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(fd);
	return;
    }
    /* Open connection. */
    httpState->connectState.fd = fd;
    httpState->connectState.host = request->host;
    httpState->connectState.port = request->port;
    httpState->connectState.handler = httpConnectDone;
    httpState->connectState.data = httpState;
    comm_nbconnect(fd, &httpState->connectState);
}

static void
httpConnectDone(int fd, int status, void *data)
{
    HttpStateData *httpState = data;
    request_t *request = httpState->request;
    StoreEntry *entry = httpState->entry;
    edge *e = NULL;
    if (status != COMM_OK) {
	if ((e = httpState->neighbor)) {
	    e->last_fail_time = squid_curtime;
	    e->neighbor_up = 0;
	}
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
    } else {
	/* Install connection complete handler. */
	if (opt_no_ipcache)
	    ipcacheInvalidate(request->host);
	fd_note(fd, entry->url);
	commSetSelect(fd, COMM_SELECT_LIFETIME,
	    httpLifetimeExpire, (void *) httpState, 0);
	commSetSelect(fd, COMM_SELECT_WRITE,
	    httpSendRequest, (void *) httpState, 0);
	if (Config.vizHackAddr.sin_port)
	    vizHackSendPkt(&httpState->connectState.S, 2);
    }
}

int
httpStart(int unusedfd,
    char *url,
    request_t * request,
    char *req_hdr,
    int req_hdr_sz,
    StoreEntry * entry)
{
    /* Create state structure. */
    int sock;
    HttpStateData *httpState = NULL;

    debug(11, 3, "httpStart: \"%s %s\"\n",
	RequestMethodStr[request->method], url);
    debug(11, 10, "httpStart: req_hdr '%s'\n", req_hdr);

    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(11, 4, "httpStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    httpState = xcalloc(1, sizeof(HttpStateData));
    storeLockObject(httpState->entry = entry, NULL, NULL);
    httpState->req_hdr = req_hdr;
    httpState->req_hdr_sz = req_hdr_sz;
    httpState->request = requestLink(request);
    comm_add_close_handler(sock,
	httpStateFree,
	(void *) httpState);
    ipcache_nbgethostbyname(request->host,
	sock,
	httpConnect,
	httpState);
    return COMM_OK;
}

void
httpReplyHeaderStats(StoreEntry * entry)
{
    http_server_cc_t i;
    storeAppendPrintf(entry, open_bracket);
    storeAppendPrintf(entry, "{HTTP Reply Headers:}\n");
    storeAppendPrintf(entry, "{       Headers parsed: %d}\n",
	ReplyHeaderStats.parsed);
    storeAppendPrintf(entry, "{                 Date: %d}\n",
	ReplyHeaderStats.date);
    storeAppendPrintf(entry, "{        Last-Modified: %d}\n",
	ReplyHeaderStats.lm);
    storeAppendPrintf(entry, "{              Expires: %d}\n",
	ReplyHeaderStats.exp);
    storeAppendPrintf(entry, "{         Content-Type: %d}\n",
	ReplyHeaderStats.ctype);
    storeAppendPrintf(entry, "{       Content-Length: %d}\n",
	ReplyHeaderStats.clen);
    for (i = 0; i < SCC_ENUM_END; i++)
	storeAppendPrintf(entry, "{Cache-Control %7.7s: %d}\n",
	    HttpServerCCStr[i],
	    ReplyHeaderStats.cc[i]);
    storeAppendPrintf(entry, close_bracket);
}
