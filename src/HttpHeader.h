
/*
 * $Id: HttpHeader.h,v 1.8 2005/12/13 21:41:57 wessels Exp $
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

#ifndef SQUID_HTTPHEADER_H
#define SQUID_HTTPHEADER_H

/* because we pass a spec by value */
#include "HttpHeaderRange.h"

/* constant attributes of http header fields */

struct _HttpHeaderFieldAttrs
{
    const char *name;
    http_hdr_type id;
    field_type type;
};

class HttpVersion;

extern int httpHeaderParseQuotedString (const char *start, String *val);
extern void httpHeaderPutSc(HttpHeader *hdr, const HttpHdrSc *sc);
extern HttpHdrSc *httpHeaderGetSc(const HttpHeader *hdr);
SQUIDCEXTERN void httpHeaderAddContRange(HttpHeader *, HttpHdrRangeSpec, ssize_t);
extern int httpHeaderHasListMember(const HttpHeader * hdr, http_hdr_type id, const char *member, const char separator);
SQUIDCEXTERN int httpHeaderHasByNameListMember(const HttpHeader * hdr, const char *name, const char *member, const char separator);
SQUIDCEXTERN void httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask);
int httpMsgIsPersistent(HttpVersion const &http_ver, const HttpHeader * hdr);

class HttpHeader
{

public:
    HttpHeader();
    HttpHeader(http_hdr_owner_type const &owner);
    ~HttpHeader();
    /* Interface functions */
    void update (HttpHeader const *fresh, HttpHeaderMask const *denied_mask);
    void removeConnectionHeaderEntries();
    /* protected, do not use these, use interface functions instead */
    Vector<HttpHeaderEntry *> entries;		/* parsed fields in raw format */
    HttpHeaderMask mask;	/* bit set <=> entry present */
    http_hdr_owner_type owner;	/* request or reply */
    int len;			/* length when packed, not counting terminating '\0' */
};

#endif /* SQUID_HTTPHEADER_H */
