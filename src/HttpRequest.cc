
/*
 * $Id: HttpRequest.cc,v 1.2 1998/05/11 18:44:28 rousskov Exp $
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

request_t *
requestCreate(method_t method, protocol_t protocol, const char *urlpath)
{
    request_t * req = memAllocate(MEM_REQUEST_T);
    req->method = method;
    req->protocol = protocol;
    if (urlpath)
	stringReset(&req->urlpath, urlpath);
    req->max_age = -1;
    req->max_forwards = -1;
    return req;
}

void
requestDestroy(request_t * req)
{
    assert(req);
    safe_free(req->prefix);
    safe_free(req->body);
    stringClean(&req->urlpath);
    httpHeaderClean(&req->header);
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
    requestDestroy(request);
}

int
httpRequestParseHeader(request_t *req, const char *parse_start)
{
    const char *blk_start, *blk_end;
    if (!httpMsgIsolateHeaders(&parse_start, &blk_start, &blk_end))
	return 0;
    return httpHeaderParse(&req->header, blk_start, blk_end);
}

void
httpRequestSetHeaders(request_t *req, method_t method, const char *uri, const char *header_str)
{
    MemBuf mb;
    assert(req && uri && header_str);
    assert(!req->prefix);

    memBufDefInit(&mb);
    memBufPrintf(&mb, "%s %s HTTP/%3.1f\r\n%s\r\n",
	RequestMethodStr[method], uri, req->http_ver, header_str);
    req->prefix = xstrdup(mb.buf);
    req->prefix_sz = mb.size;
    memBufClean(&mb);
    httpHeaderParse(&req->header, header_str, header_str+strlen(header_str));
}

/* returns true if header is allowed to be passed on */
int
httpRequestHdrAllowed(const HttpHeaderEntry *e, String *strConn)
{
    assert(e);
    /* check connection header first */
    if (strConn && strListIsMember(strConn, strBuf(e->name), ','))
	return 0;
    /* check with anonymizer tables */
    if (Config.onoff.anonymizer == ANONYMIZER_PARANOID) {
	return httpAnonHdrAllowed(e->id);
    } else
    if (Config.onoff.anonymizer == ANONYMIZER_STANDARD) {
	return !httpAnonHdrDenied(e->id);
    }
    return 1;
}

