#ifndef SQUID_REFRESHPATTERN_H_
#define SQUID_REFRESHPATTERN_H_
/*
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

#include "compat/GnuRegex.h"

/// a representation of a refresh pattern. Currently a POD.
class RefreshPattern
{
public:
    const char *pattern;
    regex_t compiled_pattern;
    time_t min;
    double pct;
    time_t max;
    RefreshPattern *next;

    struct {
        bool icase;
        bool refresh_ims;
        bool store_stale;
#if USE_HTTP_VIOLATIONS
        bool override_expire;
        bool override_lastmod;
        bool reload_into_ims;
        bool ignore_reload;
        bool ignore_no_store;
        bool ignore_must_revalidate;
        bool ignore_private;
        bool ignore_auth;
#endif
    } flags;
    int max_stale;
};

#endif /* SQUID_REFRESHPATTERN_H_ */
