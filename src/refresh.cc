
/*
 * $Id: refresh.cc,v 1.17 1997/11/12 00:09:04 wessels Exp $
 *
 * DEBUG: section 22    Refresh Calculation
 * AUTHOR: Harvest Derived
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

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"

/*
 * Defaults:
 *      MIN     NONE
 *      PCT     20%
 *      MAX     3 days
 */
#define REFRESH_DEFAULT_MIN	(time_t)0
#define REFRESH_DEFAULT_PCT	(time_t)20
#define REFRESH_DEFAULT_MAX	(time_t)259200

/*
 * refreshCheck():
 *     return 1 if its time to revalidate this entry, 0 otherwise
 */
int
refreshCheck(const StoreEntry * entry, const request_t * request, time_t delta)
{
    refresh_t *R;
    time_t min = REFRESH_DEFAULT_MIN;
    int pct = REFRESH_DEFAULT_PCT;
    time_t max = REFRESH_DEFAULT_MAX;
    const char *pattern = ".";
    time_t age;
    int factor;
    time_t check_time = squid_curtime + delta;
    debug(22, 3) ("refreshCheck: '%s'\n", storeUrl(entry));
    if (EBIT_TEST(entry->flag, ENTRY_REVALIDATE)) {
	debug(22, 3) ("refreshCheck: YES: Required Authorization\n");
	return 1;
    }
    for (R = Config.Refresh; R; R = R->next) {
	if (regexec(&(R->compiled_pattern), storeUrl(entry), 0, 0, 0) != 0)
	    continue;
	min = R->min;
	pct = R->pct;
	max = R->max;
	pattern = R->pattern;
	break;
    }
    debug(22, 3) ("refreshCheck: Matched '%s %d %d%% %d'\n",
	pattern, (int) min, pct, (int) max);
    age = check_time - entry->timestamp;
    debug(22, 3) ("refreshCheck: age = %d\n", (int) age);
    if (request->max_age > -1) {
	if (age > request->max_age) {
	    debug(22, 3) ("refreshCheck: YES: age > client-max-age\n");
	    return 1;
	}
    }
    if (age <= min) {
	debug(22, 3) ("refreshCheck: NO: age < min\n");
	return 0;
    }
    if (-1 < entry->expires) {
	if (entry->expires <= check_time) {
	    debug(22, 3) ("refreshCheck: YES: expires <= curtime\n");
	    return 1;
	} else {
	    debug(22, 3) ("refreshCheck: NO: expires > curtime\n");
	    return 0;
	}
    }
    if (age > max) {
	debug(22, 3) ("refreshCheck: YES: age > max\n");
	return 1;
    }
    if (entry->timestamp <= entry->lastmod) {
	if (request->protocol != PROTO_HTTP) {
	    debug(22, 3) ("refreshCheck: NO: non-HTTP request\n");
	    return 0;
	}
	debug(22, 3) ("refreshCheck: YES: lastvalid <= lastmod\n");
	return 1;
    }
    factor = 100 * age / (entry->timestamp - entry->lastmod);
    debug(22, 3) ("refreshCheck: factor = %d\n", factor);
    if (factor < pct) {
	debug(22, 3) ("refreshCheck: NO: factor < pct\n");
	return 0;
    }
    return 1;
}

time_t
getMaxAge(const char *url)
{
    refresh_t *R;
    debug(22, 3) ("getMaxAge: '%s'\n", url);
    for (R = Config.Refresh; R; R = R->next) {
	if (regexec(&(R->compiled_pattern), url, 0, 0, 0) == 0)
	    return R->max;
    }
    return REFRESH_DEFAULT_MAX;
}
