
/*
 * $Id: HttpHdrSc.h,v 1.3 2007/05/29 13:31:37 amosjeffries Exp $
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

#ifndef SQUID_HTTPHDRSURROGATECONTROL_H
#define SQUID_HTTPHDRSURROGATECONTROL_H

#include "dlink.h"
#include "HttpHdrScTarget.h"

/* http surogate control header field */

class HttpHdrSc
{

public:
    MEMPROXY_CLASS(HttpHdrSc);
    dlink_list targets;
};

MEMPROXY_CLASS_INLINE(HttpHdrSc);

/* Http Surrogate Control Header Field */
extern void httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);
extern void httpHdrScInitModule (void);
extern void httpHdrScCleanModule (void);
extern HttpHdrSc *httpHdrScCreate(void);
extern HttpHdrSc *httpHdrScParseCreate(String const *);
extern void httpHdrScDestroy(HttpHdrSc * sc);
extern HttpHdrSc *httpHdrScDup(const HttpHdrSc * sc);
extern void httpHdrScPackInto(const HttpHdrSc * sc, Packer * p);
extern void httpHdrScJoinWith(HttpHdrSc *, const HttpHdrSc *);
extern void httpHdrScSetMaxAge(HttpHdrSc *, char const *, int);
extern void httpHdrScUpdateStats(const HttpHdrSc *, StatHist *);
extern HttpHdrScTarget * httpHdrScFindTarget (HttpHdrSc *sc, const char *target);
extern HttpHdrScTarget * httpHdrScGetMergedTarget (HttpHdrSc *sc, const char *ourtarget);

extern void httpHeaderPutSc(HttpHeader *hdr, const HttpHdrSc *sc);
extern HttpHdrSc *httpHeaderGetSc(const HttpHeader *hdr);

#endif /* SQUID_HTTPHDRSURROGATECONTROL_H */
