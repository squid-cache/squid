
/*
 * $Id: HttpRequest.cc,v 1.12 1998/07/20 19:26:49 wessels Exp $
 *
 * DEBUG: section 73    HTTP Request
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#include "squid.h"

request_t *
requestCreate(method_t method, protocol_t protocol, const char *urlpath)
{
    request_t *req = memAllocate(MEM_REQUEST_T);
    req->method = method;
    req->protocol = protocol;
    if (urlpath)
	stringReset(&req->urlpath, urlpath);
    req->max_age = -1;
    req->max_forwards = -1;
    httpHeaderInit(&req->header, hoRequest);
    return req;
}

void
requestDestroy(request_t * req)
{
    assert(req);
    safe_free(req->body);
    safe_free(req->canonical);
    stringClean(&req->urlpath);
    httpHeaderClean(&req->header);
    if (req->cache_control)
	httpHdrCcDestroy(req->cache_control);
    if (req->range)
	httpHdrRangeDestroy(req->range);
    memFree(MEM_REQUEST_T, req);
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
    request->link_count--;
    if (request->link_count > 0)
	return;
    if (request->link_count == 0)
	requestDestroy(request);
    else
	debug(73, 1) ("requestUnlink: BUG: negative link_count: %d. Ignored.\n",
	    request->link_count);
}

int
httpRequestParseHeader(request_t * req, const char *parse_start)
{
    const char *blk_start, *blk_end;
    if (!httpMsgIsolateHeaders(&parse_start, &blk_start, &blk_end))
	return 0;
    return httpHeaderParse(&req->header, blk_start, blk_end);
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
httpRequestPack(const request_t * req, Packer *p)
{
    assert(req && p);
    /* pack request-line */
    packerPrintf(p, "%s %s HTTP/1.0\r\n",
	RequestMethodStr[req->method], strBuf(req->urlpath));
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
	strLen(req->urlpath) + 1 +
	4 + 1 + 3 + 2 +
	req->header.len + 2;
}

/* returns true if header is allowed to be passed on */
int
httpRequestHdrAllowed(const HttpHeaderEntry * e, String * strConn)
{
    assert(e);
    /* check connection header first */
    if (strConn && strListIsMember(strConn, strBuf(e->name), ','))
	return 0;
    /* check with anonymizer tables */
    if (Config.onoff.anonymizer == ANONYMIZER_PARANOID) {
	return httpAnonHdrAllowed(e->id);
    } else if (Config.onoff.anonymizer == ANONYMIZER_STANDARD) {
	return !httpAnonHdrDenied(e->id);
    }
    return 1;
}
