/*
 * HttpHeaderCacheControl.h
 *
 *  Created on: Sep 2, 2011
 *      Author: Francesco Chemolli
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
 */

#ifndef SQUID_HTTPHEADERCACHECONTROL_H_
#define SQUID_HTTPHEADERCACHECONTROL_H_

#include "config.h"
#include "MemPool.h"
#include "SquidString.h"

/* http cache control header field */
class HttpHdrCc
{

public:
    int32_t mask;
    int32_t max_age;
    int32_t s_maxage;
    int32_t max_stale;
    int32_t stale_if_error;
    int32_t min_fresh;
    String other;

    HttpHdrCc(int32_t max_age_=-1, int32_t s_maxage_=-1,
            int32_t max_stale_=-1, int32_t min_fresh_=-1) :
            mask(0), max_age(max_age_), s_maxage(s_maxage_),
            max_stale(max_stale_), stale_if_error(0),
            min_fresh(min_fresh_) {}

    MEMPROXY_CLASS(HttpHdrCc);

//TODO: make private:
    /// (re)initialize by parsing the supplied Cache-control header string
    bool parseInit(const String *s);

};

MEMPROXY_CLASS_INLINE(HttpHdrCc);

#endif /* SQUID_HTTPHEADERCACHECONTROL_H_ */
