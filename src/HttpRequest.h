
/*
 * $Id: HttpRequest.h,v 1.1 2003/01/23 00:37:13 robertc Exp $
 *
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

#ifndef SQUID_HTTPREQUEST_H
#define SQUID_HTTPREQUEST_H

#include "typedefs.h"

/*  Http Request */
extern request_t *requestCreate(method_t, protocol_t, const char *urlpath);
extern void requestDestroy(request_t *);
extern request_t *requestLink(request_t *);
extern void requestUnlink(request_t *);
extern int httpRequestParseHeader(request_t * req, const char *parse_start);
extern void httpRequestSwapOut(const request_t * req, StoreEntry * e);
extern void httpRequestPack(const request_t * req, Packer * p);
extern int httpRequestPrefixLen(const request_t * req);
extern int httpRequestHdrAllowed(const HttpHeaderEntry * e, String * strConnection);
extern int httpRequestHdrAllowedByName(http_hdr_type id);

#endif /* SQUID_HTTPREQUEST_H */
