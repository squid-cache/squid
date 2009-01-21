/*
 * $Id$
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
#ifndef SQUID_HTTPHDRSURROGATECONTROLTARGET_H
#define SQUID_HTTPHDRSURROGATECONTROLTARGET_H

class Packer;
class StoreEntry;

/* for MEMPROXY_CLASS() macros */
#include "MemPool.h"
/* for dlink_node */
#include "dlink.h"
/* for String */
#include "SquidString.h"

/** HTTP Surogate-Control: header field */
class HttpHdrScTarget
{
public:
    MEMPROXY_CLASS(HttpHdrScTarget);
    dlink_node node;
    int mask;
    int max_age;
    int max_stale;
    String content;
    String target;
};

MEMPROXY_CLASS_INLINE(HttpHdrScTarget);

/* Http Surrogate control header field 'targets' */
extern HttpHdrScTarget * httpHdrScTargetCreate (const char *);
extern void httpHdrScTargetDestroy(HttpHdrScTarget *);
extern HttpHdrScTarget *httpHdrScTargetDup(const HttpHdrScTarget *);
extern void httpHdrScTargetPackInto(const HttpHdrScTarget *, Packer *);
extern void httpHdrScTargetSetMaxAge(HttpHdrScTarget *, int);
extern void httpHdrScTargetJoinWith(HttpHdrScTarget *, const HttpHdrScTarget *);
extern void httpHdrScTargetMergeWith(HttpHdrScTarget *, const HttpHdrScTarget *);
extern void httpHdrScTargetStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);

/* for StatHist */
#include "typedefs.h"

extern void httpHdrScTargetUpdateStats(const HttpHdrScTarget *, StatHist *);


#endif /* SQUID_HTTPHDRSURROGATECONTROLTARGET_H */
