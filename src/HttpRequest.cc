
/*
 * $Id: HttpRequest.cc,v 1.51 2005/09/15 20:19:41 wessels Exp $
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

#include "squid.h"
#include "HttpRequest.h"
#include "AuthUserRequest.h"
#include "HttpHeaderRange.h"

HttpRequest::HttpRequest()  : HttpMsg(hoRequest)
{
    /* We should initialise these ... */
#if 0
    method_t method;
    char login[MAX_LOGIN_SZ];
    char host[SQUIDHOSTNAMELEN + 1];
    auth_user_request_t *auth_user_request;
    u_short port;
    String urlpath;
    char *canonical;
    int link_count;		/* free when zero */
    request_flags flags;
    HttpHdrRange *range;
    time_t ims;
    int imslen;
    int max_forwards;
    /* these in_addr's could probably be sockaddr_in's */

    struct IN_ADDR client_addr;

    struct IN_ADDR my_addr;
    unsigned short my_port;
    unsigned short client_port;
    ConnStateData::Pointer body_connection;	/* used by clientReadBody() */
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

    return req;
}

void HttpRequest::reset()
{
    clean();
    *this = HttpRequest(); // XXX: ugly; merge with clean()
}

void
requestDestroy(HttpRequest * req)
{
    assert(req);
    req->clean();
    delete req;
}

// note: this is a very low-level method that leaves us in inconsistent state
// suitable for deletion or assignment only; XXX: should be merged with reset()
void HttpRequest::clean()
{
    if (body_connection.getRaw() != NULL)
        fatal ("request being destroyed with body connection intact\n");

    if (auth_user_request)
        auth_user_request->unlock();

    safe_free(canonical);

    safe_free(vary_headers);

    urlpath.clean();

    httpHeaderClean(&header);

    if (cache_control) {
        httpHdrCcDestroy(cache_control);
        cache_control = NULL;
    }

    if (range)
        delete range;

    tag.clean();

    extacl_user.clean();

    extacl_passwd.clean();

    extacl_log.clean();
}

bool HttpRequest::sanityCheckStartLine(MemBuf *buf, http_status *error)
{
    /*
     * Just see if the request buffer starts with a known
     * HTTP request method.  NOTE this whole function is somewhat
     * superfluous and could just go away.
     */

    if (METHOD_NONE == urlParseMethod(buf->content())) {
        debug(73, 3)("HttpRequest::sanityCheckStartLine: did not find HTTP request method\n");
        return false;
    }

    return true;
}

bool HttpRequest::parseFirstLine(const char *start, const char *end)
{
    fatal("HttpRequest::parseFirstLine not implemented yet");
    return false;
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
HttpRequest::parseHeader(const char *parse_start)
{
    const char *blk_start, *blk_end;

    if (!httpMsgIsolateHeaders(&parse_start, &blk_start, &blk_end))
        return 0;

    int result = httpHeaderParse(&header, blk_start, blk_end);

    if (result)
        hdrCacheInit();

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
void
HttpRequest::hdrCacheInit()
{
    HttpMsg::hdrCacheInit();

    range = httpHeaderGetRange(&header);
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

const char *HttpRequest::packableURI(bool full_uri) const
{
    if (full_uri)
        return urlCanonical((HttpRequest*)this);

    if (urlpath.size())
        return urlpath.buf();

    return "/";
}

void HttpRequest::packFirstLineInto(Packer * p, bool full_uri) const
{
    // form HTTP request-line
    packerPrintf(p, "%s %s HTTP/%d.%d\r\n",
                 RequestMethodStr[method],
                 packableURI(full_uri),
                 http_ver.major, http_ver.minor);
}
