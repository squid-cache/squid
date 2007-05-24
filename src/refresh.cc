
/*
 * $Id: refresh.cc,v 1.76 2007/05/24 01:45:03 hno Exp $
 *
 * DEBUG: section 22    Refresh Calculation
 * AUTHOR: Harvest Derived
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

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX		/* put before includes; always use POSIX */
#endif

#include "squid.h"
#include "CacheManager.h"
#include "Store.h"
#include "MemObject.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "SquidTime.h"

typedef enum {
    rcHTTP,
    rcICP,
#if USE_HTCP
    rcHTCP,
#endif
#if USE_CACHE_DIGESTS
    rcCDigest,
#endif
    rcStore,
    rcCount
} refreshCountsEnum;

typedef struct
{
    bool expires;
    bool min;
    bool lmfactor;
    bool max;
}

stale_flags;

/*
 * This enumerated list assigns specific values, ala HTTP/FTP status
 * codes.  All Fresh codes are in the range 100-199 and all stale
 * codes are 200-299.  We might want to use these codes in logging,
 * so best to keep them consistent over time.
 */
enum {
    FRESH_REQUEST_MAX_STALE_ALL = 100,
    FRESH_REQUEST_MAX_STALE_VALUE,
    FRESH_EXPIRES,
    FRESH_LMFACTOR_RULE,
    FRESH_MIN_RULE,
    FRESH_OVERRIDE_EXPIRES,
    FRESH_OVERRIDE_LASTMOD,
    STALE_MUST_REVALIDATE = 200,
    STALE_RELOAD_INTO_IMS,
    STALE_FORCED_RELOAD,
    STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE,
    STALE_EXPIRES,
    STALE_MAX_RULE,
    STALE_LMFACTOR_RULE,
    STALE_DEFAULT = 299
};

static struct RefreshCounts
{
    const char *proto;
    int total;
    int status[STALE_DEFAULT + 1];
}

refreshCounts[rcCount];

/*
 * Defaults:
 *      MIN     NONE
 *      PCT     20%
 *      MAX     3 days
 */
#define REFRESH_DEFAULT_MIN	(time_t)0
#define REFRESH_DEFAULT_PCT	0.20
#define REFRESH_DEFAULT_MAX	(time_t)259200

static const refresh_t *refreshUncompiledPattern(const char *);
static OBJH refreshStats;
static int refreshStaleness(const StoreEntry *, time_t, time_t, const refresh_t *, stale_flags *);

static refresh_t DefaultRefresh;

const refresh_t *
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
 * Calculate how stale the response is (or will be at the check_time).
 * Staleness calculation is based on the following: (1) response
 * expiration time, (2) age greater than configured maximum, (3)
 * last-modified factor, and (4) age less than configured minimum.
 *
 * If the response is fresh, return -1.  Otherwise return its
 * staleness.  NOTE return value of 0 means the response is stale.
 *
 * The 'stale_flags' structure is used to tell the calling function
 * _why_ this response is fresh or stale.  Its used, for example,
 * when the admin wants to override expiration and last-modified
 * times.
 */
static int
refreshStaleness(const StoreEntry * entry, time_t check_time, time_t age, const refresh_t * R, stale_flags * sf)
{
    /*
     * Check for an explicit expiration time.
     */

    if (entry->expires > -1) {
        sf->expires = true;

        if (entry->expires > check_time) {
            debugs(22, 3, "FRESH: expires " << entry->expires <<
                   " >= check_time " << check_time << " ");

            return -1;
        } else {
            debugs(22, 3, "STALE: expires " << entry->expires <<
                   " < check_time " << check_time << " ");

            return (check_time - entry->expires);
        }
    }

    assert(age >= 0);
    /*
     * Use local heuristics to determine staleness.  Start with the
     * max age from the refresh_pattern rule.
     */

    if (age > R->max) {
        debugs(22, 3, "STALE: age " << age << " > max " << R->max << " ");
        sf->max = true;
        return (age - R->max);
    }

    /*
     * Try the last-modified factor algorithm.
     */
    if (entry->lastmod > -1 && entry->timestamp > entry->lastmod) {
        /*
         * stale_age is the Age of the response when it became/becomes
         * stale according to the last-modified factor algorithm.
         */
        time_t stale_age = static_cast<time_t>((entry->timestamp - entry->lastmod) * R->pct);
        sf->lmfactor = true;

        if (age >= stale_age) {
            debugs(22, 3, "STALE: age " << age << " > stale_age " << stale_age);
            return (age - stale_age);
        } else {
            debugs(22, 3, "FRESH: age " << age << " <= stale_age " << stale_age);
            return -1;
        }
    }

    /*
     * If we are here, staleness is determined by the refresh_pattern
     * configured minimum age.
     */
    if (age < R->min) {
        debugs(22, 3, "FRESH: age " << age << " < min " << R->min);
        sf->min = true;
        return -1;
    }

    debugs(22, 3, "STALE: age " << age << " >= min " << R->min);
    return (age - R->min);
}

/*  return 1 if the entry must be revalidated within delta seconds
 *         0 otherwise
 *
 *  note: request maybe null (e.g. for cache digests build)
 */
static int
refreshCheck(const StoreEntry * entry, HttpRequest * request, time_t delta)
{
    const refresh_t *R;
    const char *uri = NULL;
    time_t age = 0;
    time_t check_time = squid_curtime + delta;
    int staleness;
    stale_flags sf;

    if (entry->mem_obj)
        uri = entry->mem_obj->url;
    else if (request)
        uri = urlCanonical(request);

    debugs(22, 3, "refreshCheck: '" << (uri ? uri : "<none>") << "'");

    if (check_time > entry->timestamp)
        age = check_time - entry->timestamp;

    R = uri ? refreshLimits(uri) : refreshUncompiledPattern(".");

    if (NULL == R)
        R = &DefaultRefresh;

    memset(&sf, '\0', sizeof(sf));

    staleness = refreshStaleness(entry, check_time, age, R, &sf);

    debugs(22, 3, "Staleness = " << staleness);

    debugs(22, 3, "refreshCheck: Matched '" << R->pattern << " " <<
           (int) R->min << " " << (int) (100.0 * R->pct) << "%% " <<
           (int) R->max << "'");


    debugs(22, 3, "refreshCheck: age = " << age);

    debugs(22, 3, "\tcheck_time:\t" << mkrfc1123(check_time));

    debugs(22, 3, "\tentry->timestamp:\t" << mkrfc1123(entry->timestamp));

    if (EBIT_TEST(entry->flags, ENTRY_REVALIDATE) && staleness > -1) {
        debugs(22, 3, "refreshCheck: YES: Must revalidate stale response");
        return STALE_MUST_REVALIDATE;
    }

    /* request-specific checks */
    if (request) {
        HttpHdrCc *cc = request->cache_control;

        if (request->flags.ims && (R->flags.refresh_ims || Config.onoff.refresh_all_ims)) {
            /* The clients no-cache header is changed into a IMS query */
            debugs(22, 3, "refreshCheck: YES: refresh-ims");
            return STALE_FORCED_RELOAD;
        }

#if HTTP_VIOLATIONS

        if (!request->flags.nocache_hack) {
            (void) 0;
        } else if (R->flags.ignore_reload) {
            /* The clients no-cache header is ignored */
            debugs(22, 3, "refreshCheck: MAYBE: ignore-reload");
        } else if (R->flags.reload_into_ims || Config.onoff.reload_into_ims) {
            /* The clients no-cache header is changed into a IMS query */
            debugs(22, 3, "refreshCheck: YES: reload-into-ims");
            return STALE_RELOAD_INTO_IMS;
        } else {
            /* The clients no-cache header is not overridden on this request */
            debugs(22, 3, "refreshCheck: YES: client reload");
            request->flags.nocache = 1;
            return STALE_FORCED_RELOAD;
        }

#endif
        if (NULL != cc) {
            if (cc->max_age > -1) {
#if HTTP_VIOLATIONS
                if (R->flags.ignore_reload && cc->max_age == 0) {} else
#endif
                {
#if 0

                    if (cc->max_age == 0) {
                        debugs(22, 3, "refreshCheck: YES: client-max-age = 0");
                        return STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE;
                    }

#endif
                    if (age > cc->max_age) {
                        debugs(22, 3, "refreshCheck: YES: age > client-max-age");
                        return STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE;
                    }
                }
            }

            if (EBIT_TEST(cc->mask, CC_MAX_STALE) && staleness > -1) {
                if (cc->max_stale < 0) {
                    /* max-stale directive without a value */
                    debugs(22, 3, "refreshCheck: NO: max-stale wildcard");
                    return FRESH_REQUEST_MAX_STALE_ALL;
                } else if (staleness < cc->max_stale) {
                    debugs(22, 3, "refreshCheck: NO: staleness < max-stale");
                    return FRESH_REQUEST_MAX_STALE_VALUE;
                }
            }
        }
    }

    if (-1 == staleness) {
        debugs(22, 3, "refreshCheck: object isn't stale..");
        if (sf.expires) {
            debugs(22, 3, "refreshCheck: returning FRESH_EXPIRES");
            return FRESH_EXPIRES;
	}

        assert(!sf.max);

        if (sf.lmfactor) {
            debugs(22, 3, "refreshCheck: returning FRESH_LMFACTOR_RULE");
            return FRESH_LMFACTOR_RULE;
	}

        assert(sf.min);

        debugs(22, 3, "refreshCheck: returning FRESH_MIN_RULE");
        return FRESH_MIN_RULE;
    }

    /*
     * At this point the response is stale, unless one of
     * the override options kicks in.
     */
    if (sf.expires) {
#if HTTP_VIOLATIONS

        if (R->flags.override_expire && age < R->min) {
            debugs(22, 3, "refreshCheck: NO: age < min && override-expire");
            return FRESH_OVERRIDE_EXPIRES;
        }

#endif
        return STALE_EXPIRES;
    }

    if (sf.max)
        return STALE_MAX_RULE;

    if (sf.lmfactor) {
#if HTTP_VIOLATIONS

        if (R->flags.override_lastmod && age < R->min) {
            debugs(22, 3, "refreshCheck: NO: age < min && override-lastmod");
            return FRESH_OVERRIDE_LASTMOD;
        }

#endif
        return STALE_LMFACTOR_RULE;
    }

    debugs(22, 3, "refreshCheck: returning STALE_DEFAULT");
    return STALE_DEFAULT;
}

int
refreshIsCachable(const StoreEntry * entry)
{
    /*
     * Don't look at the request to avoid no-cache and other nuisances.
     * the object should have a mem_obj so the URL will be found there.
     * minimum_expiry_time seconds delta (defaults to 60 seconds), to 
     * avoid objects which expire almost immediately, and which can't 
     * be refreshed.
     */
    int reason = refreshCheck(entry, NULL, Config.minimum_expiry_time);
    refreshCounts[rcStore].total++;
    refreshCounts[rcStore].status[reason]++;

    if (reason < STALE_MUST_REVALIDATE)
        /* Does not need refresh. This is certainly cachable */
        return 1;

    if (entry->lastmod < 0)
        /* Last modified is needed to do a refresh */
        return 0;

    if (entry->mem_obj == NULL)
        /* no mem_obj? */
        return 1;

    if (entry->getReply() == NULL)
        /* no reply? */
        return 1;

    if (entry->getReply()->content_length == 0)
        /* No use refreshing (caching?) 0 byte objects */
        return 0;

    /* This seems to be refreshable. Cache it */
    return 1;
}

/* refreshCheck... functions below are protocol-specific wrappers around
 * refreshCheck() function above */

int
refreshCheckHTTP(const StoreEntry * entry, HttpRequest * request)
{
    int reason = refreshCheck(entry, request, 0);
    refreshCounts[rcHTTP].total++;
    refreshCounts[rcHTTP].status[reason]++;
    return (reason < 200) ? 0 : 1;
}

int
refreshCheckICP(const StoreEntry * entry, HttpRequest * request)
{
    int reason = refreshCheck(entry, request, 30);
    refreshCounts[rcICP].total++;
    refreshCounts[rcICP].status[reason]++;
    return (reason < 200) ? 0 : 1;
}

#if USE_HTCP
int
refreshCheckHTCP(const StoreEntry * entry, HttpRequest * request)
{
    int reason = refreshCheck(entry, request, 10);
    refreshCounts[rcHTCP].total++;
    refreshCounts[rcHTCP].status[reason]++;
    return (reason < 200) ? 0 : 1;
}

#endif

#if USE_CACHE_DIGESTS
int
refreshCheckDigest(const StoreEntry * entry, time_t delta)
{
    int reason = refreshCheck(entry,
                              entry->mem_obj ? entry->mem_obj->request : NULL,
                              delta);
    refreshCounts[rcCDigest].total++;
    refreshCounts[rcCDigest].status[reason]++;
    return (reason < 200) ? 0 : 1;
}

#endif

time_t
getMaxAge(const char *url)
{
    const refresh_t *R;
    debugs(22, 3, "getMaxAge: '" << url << "'");

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
    storeAppendPrintf(sentry, "Count\t%%Total\tCategory\n");

#define refreshCountsStatsEntry(code,desc) { \
	storeAppendPrintf(sentry, "%6d\t%6.2f\t%s\n", \
	    rc->status[code], xpercent(rc->status[code], tot), desc); \
    sum += rc->status[code]; \
}

    refreshCountsStatsEntry(FRESH_REQUEST_MAX_STALE_ALL,
                            "Fresh: request max-stale wildcard");
    refreshCountsStatsEntry(FRESH_REQUEST_MAX_STALE_VALUE,
                            "Fresh: request max-stale value");
    refreshCountsStatsEntry(FRESH_EXPIRES,
                            "Fresh: expires time not reached");
    refreshCountsStatsEntry(FRESH_LMFACTOR_RULE,
                            "Fresh: refresh_pattern last-mod factor percentage");
    refreshCountsStatsEntry(FRESH_MIN_RULE,
                            "Fresh: refresh_pattern min value");
    refreshCountsStatsEntry(FRESH_OVERRIDE_EXPIRES,
                            "Fresh: refresh_pattern override expires");
    refreshCountsStatsEntry(FRESH_OVERRIDE_LASTMOD,
                            "Fresh: refresh_pattern override lastmod");
    refreshCountsStatsEntry(STALE_MUST_REVALIDATE,
                            "Stale: response has must-revalidate");
    refreshCountsStatsEntry(STALE_RELOAD_INTO_IMS,
                            "Stale: changed reload into IMS");
    refreshCountsStatsEntry(STALE_FORCED_RELOAD,
                            "Stale: request has no-cache directive");
    refreshCountsStatsEntry(STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE,
                            "Stale: age exceeds request max-age value");
    refreshCountsStatsEntry(STALE_EXPIRES,
                            "Stale: expires time reached");
    refreshCountsStatsEntry(STALE_MAX_RULE,
                            "Stale: refresh_pattern max age rule");
    refreshCountsStatsEntry(STALE_LMFACTOR_RULE,
                            "Stale: refresh_pattern last-mod factor percentage");
    refreshCountsStatsEntry(STALE_DEFAULT,
                            "Stale: by default");

    tot = sum;			/* paranoid: "total" line shows 100% if we forgot nothing */
    storeAppendPrintf(sentry, "%6d\t%6.2f\tTOTAL\n",
                      rc->total, xpercent(rc->total, tot));
    \
    storeAppendPrintf(sentry, "\n");
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
refreshInit(void)
{
    memset(refreshCounts, 0, sizeof(refreshCounts));
    refreshCounts[rcHTTP].proto = "HTTP";
    refreshCounts[rcICP].proto = "ICP";
#if USE_HTCP

    refreshCounts[rcHTCP].proto = "HTCP";
#endif

    refreshCounts[rcStore].proto = "On Store";
#if USE_CACHE_DIGESTS

    refreshCounts[rcCDigest].proto = "Cache Digests";
#endif

    memset(&DefaultRefresh, '\0', sizeof(DefaultRefresh));
    DefaultRefresh.pattern = "<none>";
    DefaultRefresh.min = REFRESH_DEFAULT_MIN;
    DefaultRefresh.pct = REFRESH_DEFAULT_PCT;
    DefaultRefresh.max = REFRESH_DEFAULT_MAX;
}

void
refreshRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("refresh",
                           "Refresh Algorithm Statistics",
                           refreshStats,
                           0,
                           1);
}
