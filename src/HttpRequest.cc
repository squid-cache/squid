
/*
 * $Id: HttpRequest.cc,v 1.35 2003/02/21 22:50:05 robertc Exp $
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
 */

#include "HttpRequest.h"
#include "squid.h"
#include "authenticate.h"
#include "HttpHeaderRange.h"

static void httpRequestHdrCacheInit(request_t * req);

request_t *
requestCreate(method_t method, protocol_t protocol, const char *aUrlpath)
{
    request_t *req = static_cast<request_t *>(memAllocate(MEM_REQUEST_T));
    req->method = method;
    req->protocol = protocol;

    if (aUrlpath)
        req->urlpath = aUrlpath;

    req->max_forwards = -1;

    req->lastmod = -1;

    req->client_addr = no_addr;

    req->my_addr = no_addr;

    httpHeaderInit(&req->header, hoRequest);

    httpRequestHdrCacheInit(req);

    return req;
}

void
requestDestroy(request_t * req)
{
    assert(req);

    if (req->body_connection)
        clientAbortBody(req);

    if (req->auth_user_request)
        authenticateAuthUserRequestUnlock(req->auth_user_request);

    safe_free(req->canonical);

    safe_free(req->vary_headers);

    req->urlpath.clean();

    httpHeaderClean(&req->header);

    if (req->cache_control)
        httpHdrCcDestroy(req->cache_control);

    if (req->range)
        req->range->deleteSelf();

    memFree(req, MEM_REQUEST_T);
}

request_t *
requestLink(request_t * request)
{
    assert(request);
    request->link_count++;
    return request;
}

void
requestUnlink(request_t * request)
{
    if (!request)
        return;

    assert(request->link_count > 0);

    if (--request->link_count > 0)
        return;

    requestDestroy(request);
}

int
httpRequestParseHeader(request_t * req, const char *parse_start)
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
httpRequestSwapOut(const request_t * req, StoreEntry * e)
{
    Packer p;
    assert(req && e);
    packerToStoreInit(&p, e);
    httpRequestPack(req, &p);
    packerClean(&p);
}

/* packs request-line and headers, appends <crlf> terminator */
void
httpRequestPack(const request_t * req, Packer * p)
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
httpRequestSetHeaders(request_t * req, method_t method, const char *uri, const char *header_str)
{
    assert(req && uri && header_str);
    assert(!req->header.len);
    httpHeaderParse(&req->header, header_str, header_str + strlen(header_str));
}

#endif

/* returns the length of request line + headers + crlf */
int
httpRequestPrefixLen(const request_t * req)
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

/* sync this routine when you update request_t struct */
static void
httpRequestHdrCacheInit(request_t * req)
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
        req->content_type = StringNull;

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
request_t::multipartRangeRequest() const
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
