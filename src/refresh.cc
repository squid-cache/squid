

/*
 * $Id: refresh.cc,v 1.44 1998/11/12 06:28:23 wessels Exp $
 *
 * DEBUG: section 22    Refresh Calculation
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

typedef enum {
    rcHTTP, rcICP, rcCDigest, rcCount
} refreshCountsEnum;

static struct RefreshCounts {
    const char *proto;
    int total;
    int revalidate_stale;
    int request_max_age_stale;
    int request_reload2ims_stale;
    int request_reload_stale;
    int min_age_override_exp_fresh;
    int min_age_override_lmt_fresh;
    int response_expires_stale;
    int response_expires_fresh;
    int conf_max_age_stale;
    int last_modified_factor_fresh;
    int last_modified_factor_stale;
    int response_lmt_now_stale;
    int conf_min_age_fresh;
    int default_stale;
    /* maybe-counters -- intermediate decisions that may affect the result */
    int request_reload_ignore_maybe;
    int response_lmt_future_maybe;
} refreshCounts[rcCount];

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

/*  return 1 if the entry must be revalidated within delta seconds
 *         0 otherwise
 *
 *  note: request maybe null (e.g. for cache digests build)
 */
static int
refreshCheck(const StoreEntry * entry, request_t * request, time_t delta, struct RefreshCounts *rc)
{
    const refresh_t *R;
    const char *uri = NULL;
    time_t min = REFRESH_DEFAULT_MIN;
    double pct = REFRESH_DEFAULT_PCT;
    time_t max = REFRESH_DEFAULT_MAX;
#if HTTP_VIOLATIONS
    int override_expire = 0;
    int override_lastmod = 0;
    int reload_into_ims = 0;
    int ignore_reload = 0;
#endif
    const char *pattern = "<none>";
    time_t age;
    double factor;
    time_t check_time = squid_curtime + delta;
    if (entry->mem_obj)
	uri = entry->mem_obj->url;
    else if (request)
	uri = urlCanonical(request);

    debug(22, 3) ("refreshCheck(%s): '%s'\n", rc->proto, uri ? uri : "<none>");
    rc->total++;
    if (EBIT_TEST(entry->flags, ENTRY_REVALIDATE)) {
	debug(22, 3) ("refreshCheck: YES: Required Authorization\n");
	rc->revalidate_stale++;
	return 1;
    }
    if ((R = uri ? refreshLimits(uri) : refreshUncompiledPattern("."))) {
	min = R->min;
	pct = R->pct;
	max = R->max;
	pattern = R->pattern;
#if HTTP_VIOLATIONS
	override_expire = R->flags.override_expire;
	override_lastmod = R->flags.override_lastmod;
	reload_into_ims = R->flags.reload_into_ims;
	ignore_reload = R->flags.ignore_reload;
#endif
    }
#if HTTP_VIOLATIONS
    if (!reload_into_ims)
	reload_into_ims = Config.onoff.reload_into_ims;
#endif
    debug(22, 3) ("refreshCheck: Matched '%s %d %d%% %d'\n",
	pattern, (int) min, (int) (100.0 * pct), (int) max);
    age = check_time - entry->timestamp;
    debug(22, 3) ("refreshCheck: age = %d\n", (int) age);
    debug(22, 3) ("\tcheck_time:\t%s\n", mkrfc1123(check_time));
    debug(22, 3) ("\tentry->timestamp:\t%s\n", mkrfc1123(entry->timestamp));
    /* request-specific checks */
    if (request) {
#if HTTP_VIOLATIONS
	if (request->flags.nocache_hack) {
	    if (ignore_reload) {
		/* The clients no-cache header is ignored */
		debug(22, 3) ("refreshCheck: MAYBE: ignore-reload\n");
		rc->request_reload_ignore_maybe++;
	    } else if (reload_into_ims) {
		/* The clients no-cache header is changed into a IMS query */
		debug(22, 3) ("refreshCheck: YES: reload-into-ims\n");
		rc->request_reload2ims_stale++;
		return 1;
	    } else {
		/* The clients no-cache header is not overridden on this request */
		debug(22, 3) ("refreshCheck: YES: client reload\n");
		request->flags.nocache = 1;
		rc->request_reload_stale++;
		return 1;
	    }
	}
#endif
	if (request->max_age > -1) {
	    if (age > request->max_age) {
		debug(22, 3) ("refreshCheck: YES: age > client-max-age\n");
		rc->request_max_age_stale++;
		return 1;
	    }
	}
    }
#if HTTP_VIOLATIONS
    if (override_expire && age <= min) {
	debug(22, 3) ("refreshCheck: NO: age < min && override_expire\n");
	rc->min_age_override_exp_fresh++;
	return 0;
    }
#endif
    if (entry->expires > -1) {
	if (entry->expires <= check_time) {
	    debug(22, 3) ("refreshCheck: YES: expires <= curtime\n");
	    rc->response_expires_stale++;
	    return 1;
	} else {
	    debug(22, 3) ("refreshCheck: NO: expires > curtime\n");
	    rc->response_expires_fresh++;
	    return 0;
	}
    }
    if (age > max) {
	debug(22, 3) ("refreshCheck: YES: age > max\n");
	rc->conf_max_age_stale++;
	return 1;
    }
#if HTTP_VIOLATIONS
    if (override_lastmod && age <= min) {
	debug(22, 3) ("refreshCheck: NO: age < min && override_lastmod\n");
	rc->min_age_override_lmt_fresh++;
	return 0;
    }
#endif
    if (entry->lastmod > -1 && entry->timestamp > entry->lastmod) {
	factor = (double) age / (double) (entry->timestamp - entry->lastmod);
	debug(22, 3) ("refreshCheck: factor = %f\n", factor);
	if (factor < pct) {
	    debug(22, 3) ("refreshCheck: NO: factor < pct\n");
	    rc->last_modified_factor_fresh++;
	    return 0;
	} else {
	    debug(22, 3) ("refreshCheck: YES: factor >= pct\n");
	    rc->last_modified_factor_stale++;
	    return 1;
	}
    } else if (entry->lastmod > -1 && entry->timestamp == entry->lastmod) {
	debug(22, 3) ("refreshCheck: YES: last-modified 'now'\n");
	rc->response_lmt_now_stale++;
	return 1;
    } else if (entry->lastmod > -1 && entry->timestamp < entry->lastmod) {
	debug(22, 3) ("refreshCheck: MAYBE: last-modified in the future\n");
	rc->response_lmt_future_maybe++;
    }
    if (age <= min) {
	debug(22, 3) ("refreshCheck: NO: age <= min\n");
	rc->conf_min_age_fresh++;
	return 0;
    }
    debug(22, 3) ("refreshCheck: YES: default stale\n");
    rc->default_stale++;
    return 1;
}

/* refreshCheck... functions below are protocol-specific wrappers around
 * refreshCheck() function above */

int
refreshCheckHTTP(const StoreEntry * entry, request_t * request)
{
    return refreshCheck(entry, request, 0, &refreshCounts[rcHTTP]);
}

int
refreshCheckICP(const StoreEntry * entry, request_t * request)
{
    return refreshCheck(entry, request, 30, &refreshCounts[rcICP]);
}

int
refreshCheckDigest(const StoreEntry * entry, time_t delta)
{
    return refreshCheck(entry,
	entry->mem_obj ? entry->mem_obj->request : NULL,
	delta,
	&refreshCounts[rcCDigest]);
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
refreshCountsStats(StoreEntry * sentry, struct RefreshCounts *rc)
{
    int sum = 0;
    int tot = rc->total;

    storeAppendPrintf(sentry, "\n\n%s histogram:\n", rc->proto);
    storeAppendPrintf(sentry, "Category\tCount\t%%Total\n");

#define refreshCountsStatsEntry(name) { \
    if (rc->name || !strcmp(#name, "total")) \
	storeAppendPrintf(sentry, "%s\t%6d\t%6.2f\n", \
	    #name, rc->name, xpercent(rc->name, tot)); \
    sum += rc->name; \
}
    refreshCountsStatsEntry(revalidate_stale);
    refreshCountsStatsEntry(request_reload2ims_stale);
    refreshCountsStatsEntry(request_reload_stale);
    refreshCountsStatsEntry(request_max_age_stale);
    refreshCountsStatsEntry(min_age_override_exp_fresh);
    refreshCountsStatsEntry(response_expires_stale);
    refreshCountsStatsEntry(response_expires_fresh);
    refreshCountsStatsEntry(conf_max_age_stale);
    refreshCountsStatsEntry(min_age_override_lmt_fresh);
    refreshCountsStatsEntry(last_modified_factor_fresh);
    refreshCountsStatsEntry(last_modified_factor_stale);
    refreshCountsStatsEntry(response_lmt_now_stale);
    refreshCountsStatsEntry(conf_min_age_fresh);
    refreshCountsStatsEntry(default_stale);
    tot = sum;			/* paranoid: "total" line shows 100% if we forgot nothing */
    refreshCountsStatsEntry(total);
    /* maybe counters */
    refreshCountsStatsEntry(request_reload_ignore_maybe);
    refreshCountsStatsEntry(response_lmt_future_maybe);
}

static void
refreshStats(StoreEntry * sentry)
{
    int i;
    int total = 0;

    /* get total usage count */
    for (i = 0; i < rcCount; ++i)
	total += refreshCounts[i].total;

    /* protocol usage histogram */
    storeAppendPrintf(sentry, "\nRefreshCheck calls per protocol\n\n");
    storeAppendPrintf(sentry, "Protocol\t#Calls\t%%Calls\n");
    for (i = 0; i < rcCount; ++i)
	storeAppendPrintf(sentry, "%10s\t%6d\t%6.2f\n",
	    refreshCounts[i].proto,
	    refreshCounts[i].total,
	    xpercent(refreshCounts[i].total, total));

    /* per protocol histograms */
    storeAppendPrintf(sentry, "\n\nRefreshCheck histograms for various protocols\n");
    for (i = 0; i < rcCount; ++i)
	refreshCountsStats(sentry, &refreshCounts[i]);
}

void
refreshInit()
{
    memset(refreshCounts, 0, sizeof(refreshCounts));
    refreshCounts[rcHTTP].proto = "HTTP";
    refreshCounts[rcICP].proto = "ICP";
    refreshCounts[rcCDigest].proto = "Cache Digests";

    cachemgrRegister("refresh",
	"Refresh Algorithm Statistics",
	refreshStats,
	0,
	1);
}
