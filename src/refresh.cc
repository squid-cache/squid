
/*
 * $Id: refresh.cc,v 1.27 1998/07/21 17:26:40 wessels Exp $
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"

struct {
    int total;
    int revalidate_stale;
    int request_max_age_stale;
    int response_expires_stale;
    int response_expires_fresh;
    int conf_max_age_stale;
    int last_modified_factor_fresh;
    int last_modified_factor_stale;
    int conf_min_age_fresh;
    int default_stale;
} refreshCounts;

/*
 * Defaults:
 *      MIN     NONE
 *      PCT     20%
 *      MAX     3 days
 */
#define REFRESH_DEFAULT_MIN	(time_t)0
#define REFRESH_DEFAULT_PCT	0.20
#define REFRESH_DEFAULT_MAX	(time_t)259200

static const refresh_t *refreshLimits(const char *);
static const refresh_t *refreshUncompiledPattern(const char *);
static OBJH refreshStats;

static const refresh_t *
refreshLimits(const char *url)
{
    const refresh_t *R;
    for (R = Config.Refresh; R; R = R->next) {
	if (!regexec(&(R->compiled_pattern), url, 0, 0, 0))
	    return R;
    }
    return NULL;
}

static const refresh_t *
refreshUncompiledPattern(const char *pat)
{
    const refresh_t *R;
    for (R = Config.Refresh; R; R = R->next) {
	if (0 == strcmp(R->pattern, pat))
	    return R;
    }
    return NULL;
}

/*
 * refreshCheck():
 *     return 1 if its time to revalidate this entry, 0 otherwise
 */
int
refreshCheck(const StoreEntry * entry, request_t * request, time_t delta)
{
    const refresh_t *R;
    const char *uri;
    time_t min = REFRESH_DEFAULT_MIN;
    double pct = REFRESH_DEFAULT_PCT;
    time_t max = REFRESH_DEFAULT_MAX;
    const char *pattern = ".";
    time_t age;
    double factor;
    time_t check_time = squid_curtime + delta;
    if (entry->mem_obj)
	uri = entry->mem_obj->url;
    else
	uri = urlCanonical(request);
    debug(22, 3) ("refreshCheck: '%s'\n", uri);
    refreshCounts.total++;
    if (EBIT_TEST(entry->flag, ENTRY_REVALIDATE)) {
	debug(22, 3) ("refreshCheck: YES: Required Authorization\n");
	refreshCounts.revalidate_stale++;
	return 1;
    }
    if ((R = refreshLimits(uri))) {
	min = R->min;
	pct = R->pct;
	max = R->max;
	pattern = R->pattern;
    }
    debug(22, 3) ("refreshCheck: Matched '%s %d %d%% %d'\n",
	pattern, (int) min, (int) (100.0 * pct), (int) max);
    age = check_time - entry->timestamp;
    debug(22, 3) ("refreshCheck: age = %d\n", (int) age);
    debug(22, 3) ("\tcheck_time:\t%s\n", mkrfc1123(check_time));
    debug(22, 3) ("\tentry->timestamp:\t%s\n", mkrfc1123(entry->timestamp));
    if (request->max_age > -1) {
	if (age > request->max_age) {
	    debug(22, 3) ("refreshCheck: YES: age > client-max-age\n");
	    refreshCounts.request_max_age_stale++;
	    return 1;
	}
    }
    if (entry->expires > -1) {
	if (entry->expires <= check_time) {
	    debug(22, 3) ("refreshCheck: YES: expires <= curtime\n");
	    refreshCounts.response_expires_stale++;
	    return 1;
	} else {
	    debug(22, 3) ("refreshCheck: NO: expires > curtime\n");
	    refreshCounts.response_expires_fresh++;
	    return 0;
	}
    }
    if (age > max) {
	debug(22, 3) ("refreshCheck: YES: age > max\n");
	refreshCounts.conf_max_age_stale++;
	return 1;
    }
    if (entry->lastmod > -1 && entry->timestamp > entry->lastmod) {
	factor = (double) age / (double) (entry->timestamp - entry->lastmod);
	debug(22, 3) ("refreshCheck: factor = %f\n", factor);
	if (factor < pct) {
	    debug(22, 3) ("refreshCheck: NO: factor < pct\n");
	    refreshCounts.last_modified_factor_fresh++;
	    return 0;
	} else {
	    debug(22, 3) ("refreshCheck: YES: factor >= pct\n");
	    refreshCounts.last_modified_factor_stale++;
	    return 1;
	}
    }
    if (age <= min) {
	debug(22, 3) ("refreshCheck: NO: age < min\n");
	refreshCounts.conf_min_age_fresh++;
	return 0;
    }
    refreshCounts.default_stale++;
    return 1;
}

/* returns an approximate time when refreshCheck() may return true */
time_t
refreshWhen(const StoreEntry * entry)
{
    const refresh_t *R;
    time_t refresh_time = squid_curtime;
    time_t min = REFRESH_DEFAULT_MIN;
    time_t max = REFRESH_DEFAULT_MAX;
    double pct = REFRESH_DEFAULT_PCT;
    const char *pattern = ".";
    if (entry->mem_obj) {
	assert(entry->mem_obj->url);
	debug(22, 3) ("refreshWhen: key '%s'\n", storeKeyText(entry->key));
	debug(22, 3) ("refreshWhen: url '%s'\n", entry->mem_obj->url);
	if (EBIT_TEST(entry->flag, ENTRY_REVALIDATE)) {
	    debug(22, 3) ("refreshWhen: NOW: Required Authorization\n");
	    return refresh_time;
	}
	debug(22, 3) ("refreshWhen: entry: exp: %d, tstamp: %d, lmt: %d\n",
	    entry->expires, entry->timestamp, entry->lastmod);
	R = refreshLimits(entry->mem_obj->url);
    } else {
	R = refreshUncompiledPattern(".");
    }
    if (R != NULL) {
	min = R->min;
	max = R->max;
	pct = R->pct;
	pattern = R->pattern;
    }
    debug(22, 3) ("refreshWhen: Matched '%s %d %d%% %d'\n",
	pattern, (int) min, (int) (100.0 * pct), (int) max);
    /* convert to absolute numbers */
    min += entry->timestamp;
    max += entry->timestamp;
    if (-1 < entry->expires) {
	debug(22, 3) ("refreshWhen: expires set\n");
	refresh_time = entry->expires;
    } else if (entry->timestamp <= entry->lastmod) {
	debug(22, 3) ("refreshWhen: lastvalid <= lastmod\n");
	refresh_time = squid_curtime;
    } else {
	refresh_time = (entry->timestamp - entry->lastmod) * pct + entry->timestamp;
	debug(22, 3) ("refreshWhen: using refresh pct\n");
    }
    /* take min/max into account, max takes priority over min */
    if (refresh_time < min)
	refresh_time = min;
    if (refresh_time > max)
	refresh_time = max;
    debug(22, 3) ("refreshWhen: answer: %d (in %d secs)\n",
	refresh_time, (int) (refresh_time - squid_curtime));
    return refresh_time;
}

time_t
getMaxAge(const char *url)
{
    const refresh_t *R;
    debug(22, 3) ("getMaxAge: '%s'\n", url);
    if ((R = refreshLimits(url)))
	return R->max;
    else
	return REFRESH_DEFAULT_MAX;
}

static void
refreshStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "refreshCounts.total\t%d\n",
	refreshCounts.total);
    storeAppendPrintf(sentry, "refreshCounts.revalidate_stale\t%d\n",
	refreshCounts.revalidate_stale);
    storeAppendPrintf(sentry, "refreshCounts.request_max_age_stale\t%d\n",
	refreshCounts.request_max_age_stale);
    storeAppendPrintf(sentry, "refreshCounts.response_expires_stale\t%d\n",
	refreshCounts.response_expires_stale);
    storeAppendPrintf(sentry, "refreshCounts.response_expires_fresh\t%d\n",
	refreshCounts.response_expires_fresh);
    storeAppendPrintf(sentry, "refreshCounts.conf_max_age_stale\t%d\n",
	refreshCounts.conf_max_age_stale);
    storeAppendPrintf(sentry, "refreshCounts.last_modified_factor_fresh\t%d\n",
	refreshCounts.last_modified_factor_fresh);
    storeAppendPrintf(sentry, "refreshCounts.last_modified_factor_stale\t%d\n",
	refreshCounts.last_modified_factor_stale);
    storeAppendPrintf(sentry, "refreshCounts.conf_min_age_fresh\t%d\n",
	refreshCounts.conf_min_age_fresh);
    storeAppendPrintf(sentry, "refreshCounts.default_stale\t%d\n",
	refreshCounts.default_stale);
}

void
refreshInit(void)
{
    cachemgrRegister("refresh",
	"Refresh Algorithm Statistics",
	refreshStats,
	0,
	1);
}
