
/*
 * $Id: HttpRequest.cc,v 1.44 2003/08/14 12:15:04 robertc Exp $
 *
 * DEBUG: section 73    HTTP Request
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "HttpRequest.h"
#include "squid.h"
#include "authenticate.h"
#include "HttpHeaderRange.h"

static void httpRequestHdrCacheInit(HttpRequest * req);
MemPool (*HttpRequest::Pool)(NULL);

void *
HttpRequest::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (HttpRequest));

    if (!Pool)
        Pool = memPoolCreate("HttpRequest", sizeof (HttpRequest));

    return memPoolAlloc(Pool);
}

void
HttpRequest::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

HttpRequest::HttpRequest()  : header(hoRequest)
{
    /* We should initialise these ... */
#if 0
    method_t method;
    protocol_t protocol;
    char login[MAX_LOGIN_SZ];
    char host[SQUIDHOSTNAMELEN + 1];
    auth_user_request_t *auth_user_request;
    u_short port;
    String urlpath;
    char *canonical;
    int link_count;		/* free when zero */
    request_flags flags;
    HttpHdrCc *cache_control;
    HttpHdrRange *range;
    http_version_t http_ver;
    time_t ims;
    int imslen;
    int max_forwards;
    /* these in_addr's could probably be sockaddr_in's */

    struct in_addr client_addr;

    struct in_addr my_addr;
    unsigned short my_port;
    unsigned short client_port;
    HttpHeader header;
    ConnStateData::Pointer body_connection;	/* used by clientReadBody() */
    int content_length;
    HierarchyLogEntry hier;
    err_type errType;
    char *peer_login;		/* Configured peer login:password */
    time_t lastmod;		/* Used on refreshes */
    const char *vary_headers;	/* Used when varying entities are detected. Changes how the store key is calculated */
    char *peer_domain;		/* Configured peer forceddomain */
#endif
}

HttpRequest *
requestCreate(method_t method, protocol_t protocol, const char *aUrlpath)
{
    HttpRequest *req = new HttpRequest;
    req->method = method;
    req->protocol = protocol;

    if (aUrlpath)
        req->urlpath = aUrlpath;

    req->max_forwards = -1;

    req->lastmod = -1;

    req->client_addr = no_addr;

    req->my_addr = no_addr;

    httpRequestHdrCacheInit(req);

    return req;
}

void
requestDestroy(HttpRequest * req)
{
    assert(req);

    if (req->body_connection.getRaw() != NULL)
        fatal ("request being destroyed with body connection intact\n");

    if (req->auth_user_request)
        authenticateAuthUserRequestUnlock(req->auth_user_request);

    safe_free(req->canonical);

    safe_free(req->vary_headers);

    req->urlpath.clean();

    httpHeaderClean(&req->header);

    if (req->cache_control)
        httpHdrCcDestroy(req->cache_control);

    if (req->range)
        delete req->range;

    req->tag.clean();

    req->extacl_user.clean();

    req->extacl_passwd.clean();

    req->extacl_log.clean();

    delete req;
}

HttpRequest *
requestLink(HttpRequest * request)
{
    assert(request);
    request->link_count++;
    return request;
}

void
requestUnlink(HttpRequest * request)
{
    if (!request)
        return;

    assert(request->link_count > 0);

    if (--request->link_count > 0)
        return;

    requestDestroy(request);
}

int
httpRequestParseHeader(HttpRequest * req, const char *parse_start)
{
    const char *blk_start, *blk_end;

    if (!httpMsgIsolateHeaders(&parse_start, &blk_start, &blk_end))
        return 0;

    int result = httpHeaderParse(&req->header, blk_start, blk_end);

    if (result)
        httpRequestHdrCacheInit(req);

    return result;
}

/* swaps out request using httpRequestPack */
void
httpRequestSwapOut(const HttpRequest * req, StoreEntry * e)
{
    Packer p;
    assert(req && e);
    packerToStoreInit(&p, e);
    httpRequestPack(req, &p);
    packerClean(&p);
}

/* packs request-line and headers, appends <crlf> terminator */
void
httpRequestPack(const HttpRequest * req, Packer * p)
{
    assert(req && p);
    /* pack request-line */
    packerPrintf(p, "%s %s HTTP/1.0\r\n",
                 RequestMethodStr[req->method], req->urlpath.buf());
    /* headers */
    httpHeaderPackInto(&req->header, p);
    /* trailer */
    packerAppend(p, "\r\n", 2);
}

#if UNUSED_CODE
void
httpRequestSetHeaders(HttpRequest * req, method_t method, const char *uri, const char *header_str)
{
    assert(req && uri && header_str);
    assert(!req->header.len);
    httpHeaderParse(&req->header, header_str, header_str + strlen(header_str));
}

#endif

/* returns the length of request line + headers + crlf */
int
httpRequestPrefixLen(const HttpRequest * req)
{
    assert(req);
    return strlen(RequestMethodStr[req->method]) + 1 +
           req->urlpath.size() + 1 +
           4 + 1 + 3 + 2 +
           req->header.len + 2;
}

/*
 * Returns true if HTTP allows us to pass this header on.  Does not
 * check anonymizer (aka header_access) configuration.
 */
int
httpRequestHdrAllowed(const HttpHeaderEntry * e, String * strConn)
{
    assert(e);
    /* check connection header */

    if (strConn && strListIsMember(strConn, e->name.buf(), ','))
        return 0;

    return 1;
}

/* sync this routine when you update HttpRequest struct */
static void
httpRequestHdrCacheInit(HttpRequest * req)
{
    const HttpHeader *hdr = &req->header;
    /*  const char *str; */
    req->content_length = httpHeaderGetInt(hdr, HDR_CONTENT_LENGTH);
    /* TODO: canonicalise these into an HttpEntity */
#if 0

    req->date = httpHeaderGetTime(hdr, HDR_DATE);
    req->last_modified = httpHeaderGetTime(hdr, HDR_LAST_MODIFIED);
    str = httpHeaderGetStr(hdr, HDR_CONTENT_TYPE);

    if (str)
        stringLimitInit(&req->content_type, str, strcspn(str, ";\t "));
    else
        req->content_type = String();

#endif

    req->cache_control = httpHeaderGetCc(hdr);

    req->range = httpHeaderGetRange(hdr);

#if 0

    req->keep_alive = httpMsgIsPersistent(req->http_ver, &req->header);

    /* be sure to set expires after date and cache-control */
    req->expires = httpReplyHdrExpirationTime(req);

#endif
}

/* request_flags */
bool
request_flags::resetTCP() const
{
    return reset_tcp != 0;
}

void
request_flags::setResetTCP()
{
    debug (73, 9) ("request_flags::setResetTCP\n");
    reset_tcp = 1;
}

void
request_flags::clearResetTCP()
{
    debug(73, 9) ("request_flags::clearResetTCP\n");
    reset_tcp = 0;
}

bool
HttpRequest::multipartRangeRequest() const
{
    return (range && range->specs.count > 1);
}

void
request_flags::destinationIPLookupCompleted()
{
    destinationIPLookedUp_ = true;
}

bool
request_flags::destinationIPLookedUp() const
{
    return destinationIPLookedUp_;
}
