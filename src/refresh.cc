/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 22    Refresh Calculation */

#ifndef USE_POSIX_REGEX
#define USE_POSIX_REGEX     /* put before includes; always use POSIX */
#endif

#include "squid.h"
#include "HttpHdrCc.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "RefreshPattern.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "URL.h"

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

/**
 * Flags indicating which staleness algorithm has been applied.
 */
typedef struct {
    bool expires;  ///< Expires: header absolute timestamp limit
    bool min;      ///< Heuristic minimum age limited
    bool lmfactor; ///< Last-Modified with heuristic determines limit
    bool max;      ///< Configured maximum age limit
} stale_flags;

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
    STALE_MAX_STALE,
    STALE_DEFAULT = 299
};

static struct RefreshCounts {
    const char *proto;
    int total;
    int status[STALE_DEFAULT + 1];
} refreshCounts[rcCount];

/*
 * Defaults:
 *      MIN     NONE
 *      PCT     20%
 *      MAX     3 days
 */
#define REFRESH_DEFAULT_MIN (time_t)0
#define REFRESH_DEFAULT_PCT 0.20
#define REFRESH_DEFAULT_MAX (time_t)259200

static const RefreshPattern *refreshUncompiledPattern(const char *);
static OBJH refreshStats;
static int refreshStaleness(const StoreEntry * entry, time_t check_time, const time_t age, const RefreshPattern * R, stale_flags * sf);

static RefreshPattern DefaultRefresh;

/** Locate the first refresh_pattern rule that matches the given URL by regex.
 *
 * \note regexec() returns 0 if matched, and REG_NOMATCH otherwise
 *
 * \return A pointer to the refresh_pattern parameters to use, or NULL if there is no match.
 */
const RefreshPattern *
refreshLimits(const char *url)
{
    const RefreshPattern *R;

    for (R = Config.Refresh; R; R = R->next) {
        if (!regexec(&(R->compiled_pattern), url, 0, 0, 0))
            return R;
    }

    return NULL;
}

/** Locate the first refresh_pattern rule that has the given uncompiled regex.
 *
 * \note There is only one reference to this function, below. It always passes "." as the pattern.
 * This function is only ever called if there is no URI. Because a regex match is impossible, Squid
 * forces the "." rule to apply (if it exists)
 *
 * \return A pointer to the refresh_pattern parameters to use, or NULL if there is no match.
 */
static const RefreshPattern *
refreshUncompiledPattern(const char *pat)
{
    const RefreshPattern *R;

    for (R = Config.Refresh; R; R = R->next) {
        if (0 == strcmp(R->pattern, pat))
            return R;
    }

    return NULL;
}

/**
 * Calculate how stale the response is (or will be at the check_time).
 *
 * We try the following ways until one gives a result:
 *
 * 1. response expiration time, if one was set
 * 2. age greater than configured maximum
 * 3. last-modified factor algorithm
 * 4. age less than configured minimum
 * 5. default (stale)
 *
 * \param entry       the StoreEntry being examined
 * \param check_time  the time (maybe future) at which we want to know whether $
 * \param age         the age of the entry at check_time
 * \param R           the refresh_pattern rule that matched this entry
 * \param sf          small struct to indicate reason for stale/fresh decision
 *
 * \retval -1  If the response is fresh.
 * \retval >0  The amount of staleness.
 * \retval 0   NOTE return value of 0 means the response is stale.
 */
static int
refreshStaleness(const StoreEntry * entry, time_t check_time, const time_t age, const RefreshPattern * R, stale_flags * sf)
{
    // 1. If the cached object has an explicit expiration time, then we rely on this and
    //    completely ignore the Min, Percent and Max values in the refresh_pattern.
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

    debugs(22, 3, "No explicit expiry given, using heuristics to determine freshness");

    // 2. If the entry is older than the maximum age in the refresh_pattern, it is STALE.
    if (age > R->max) {
        debugs(22, 3, "STALE: age " << age << " > max " << R->max << " ");
        sf->max = true;
        return (age - R->max);
    }

    // 3. If there is a Last-Modified header, try the last-modified factor algorithm.
    if (entry->lastmod > -1 && entry->timestamp > entry->lastmod) {

        /* lastmod_delta is the difference between the last-modified date of the response
         * and the time we cached it. It's how "old" the response was when we got it.
         */
        time_t lastmod_delta = entry->timestamp - entry->lastmod;

        /* stale_age is the age of the response when it became/becomes stale according to
         * the last-modified factor algorithm. It's how long we can consider the response
         * fresh from the time we cached it.
         */
        time_t stale_age = static_cast<time_t>(lastmod_delta * R->pct);

        debugs(22,3, "Last modified " << lastmod_delta << " sec before we cached it, L-M factor " <<
               (100.0 * R->pct) << "% = " << stale_age << " sec freshness lifetime");
        sf->lmfactor = true;

        if (age >= stale_age) {
            debugs(22, 3, "STALE: age " << age << " > stale_age " << stale_age);
            return (age - stale_age);
        } else {
            debugs(22, 3, "FRESH: age " << age << " <= stale_age " << stale_age);
            return -1;
        }
    }

    // 4. If the entry is not as old as the minimum age in the refresh_pattern, it is FRESH.
    if (age < R->min) {
        debugs(22, 3, "FRESH: age (" << age << " sec) is less than configured minimum (" << R->min << " sec)");
        sf->min = true;
        return -1;
    }

    // 5. default is stale, by the amount we missed the minimum by
    debugs(22, 3, "STALE: No explicit expiry, no last modified, and older than configured minimum.");
    return (age - R->min);
}

/** Checks whether a store entry is fresh or stale, and why.
 *
 * This is where all aspects of request, response and squid configuration
 * meet to decide whether a response is cacheable or not:
 *
 * 1. Client request headers that affect cacheability, e.g.
 *  - Cache-Control: no-cache
 *  - Cache-Control: max-age=N
 *  - Cache-Control: max-stale[=N]
 *  - Pragma: no-cache
 *
 * 2. Server response headers that affect cacheability, e.g.
 *  - Age:
 *  - Cache-Control: proxy-revalidate
 *  - Cache-Control: must-revalidate
 *  - Cache-Control: no-cache
 *  - Cache-Control: max-age=N
 *  - Cache-Control: s-maxage=N
 *  - Date:
 *  - Expires:
 *  - Last-Modified:
 *
 * 3. Configuration options, e.g.
 *  - reload-into-ims (refresh_pattern)
 *  - ignore-reload (refresh_pattern)
 *  - refresh-ims (refresh_pattern)
 *  - override-lastmod (refresh_pattern)
 *  - override-expire (refresh_pattern)
 *  - reload_into_ims (global option)
 *  - refresh_all_ims (global option)
 *
 * \returns a status code (from enum above):
 *  - FRESH_REQUEST_MAX_STALE_ALL
 *  - FRESH_REQUEST_MAX_STALE_VALUE
 *  - FRESH_EXPIRES
 *  - FRESH_LMFACTOR_RULE
 *  - FRESH_MIN_RULE
 *  - FRESH_OVERRIDE_EXPIRES
 *  - FRESH_OVERRIDE_LASTMOD
 *  - STALE_MUST_REVALIDATE
 *  - STALE_RELOAD_INTO_IMS
 *  - STALE_FORCED_RELOAD
 *  - STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE
 *  - STALE_EXPIRES
 *  - STALE_MAX_RULE
 *  - STALE_LMFACTOR_RULE
 *  - STALE_MAX_STALE
 *  - STALE_DEFAULT
 *
 * \note request may be NULL (e.g. for cache digests build)
 *
 * \note the store entry being examined is not necessarily cached (e.g. if
 *       this response is being evaluated for the first time)
 */
static int
refreshCheck(const StoreEntry * entry, HttpRequest * request, time_t delta)
{
    const char *uri = NULL;
    time_t age = 0;
    time_t check_time = squid_curtime + delta;
    int staleness;
    stale_flags sf;

    // get the URL of this entry, if there is one
    if (entry->mem_obj)
        uri = entry->mem_obj->storeId();
    else if (request)
        uri = urlCanonical(request);

    debugs(22, 3, "checking freshness of '" << (uri ? uri : "<none>") << "'");

    // age is not necessarily the age now, but the age at the given check_time
    if (check_time > entry->timestamp)
        age = check_time - entry->timestamp;

    // FIXME: what to do when age < 0 or counter overflow?
    assert(age >= 0);

    /* We need a refresh rule. In order of preference:
     *
     *   1. the rule that matches this URI by regex
     *   2. the "." rule from the config file
     *   3. the default "." rule
     */
    const RefreshPattern *R = uri ? refreshLimits(uri) : refreshUncompiledPattern(".");
    if (NULL == R)
        R = &DefaultRefresh;

    debugs(22, 3, "Matched '" << R->pattern << " " <<
           (int) R->min << " " << (int) (100.0 * R->pct) << "%% " <<
           (int) R->max << "'");

    debugs(22, 3, "\tage:\t" << age);

    debugs(22, 3, "\tcheck_time:\t" << mkrfc1123(check_time));

    debugs(22, 3, "\tentry->timestamp:\t" << mkrfc1123(entry->timestamp));

    if (request && !request->flags.ignoreCc) {
        const HttpHdrCc *const cc = request->cache_control;
        if (cc && cc->hasMinFresh()) {
            const int32_t minFresh=cc->minFresh();
            debugs(22, 3, "\tage + min-fresh:\t" << age << " + " <<
                   minFresh << " = " << age + minFresh);
            debugs(22, 3, "\tcheck_time + min-fresh:\t" << check_time << " + "
                   << minFresh << " = " <<
                   mkrfc1123(check_time + minFresh));
            age += minFresh;
            check_time += minFresh;
        }
    }

    memset(&sf, '\0', sizeof(sf));

    staleness = refreshStaleness(entry, check_time, age, R, &sf);

    debugs(22, 3, "Staleness = " << staleness);

    // stale-if-error requires any failure be passed thru when its period is over.
    if (request && entry->mem_obj && entry->mem_obj->getReply() && entry->mem_obj->getReply()->cache_control &&
            entry->mem_obj->getReply()->cache_control->hasStaleIfError() &&
            entry->mem_obj->getReply()->cache_control->staleIfError() < staleness) {

        debugs(22, 3, "stale-if-error period expired. Will produce error if validation fails.");
        request->flags.failOnValidationError = true;
    }

    /* If the origin server specified either of:
     *   Cache-Control: must-revalidate
     *   Cache-Control: proxy-revalidate
     * the spec says the response must always be revalidated if stale.
     */
    if (EBIT_TEST(entry->flags, ENTRY_REVALIDATE) && staleness > -1
#if USE_HTTP_VIOLATIONS
            && !R->flags.ignore_must_revalidate
#endif
       ) {
        debugs(22, 3, "YES: Must revalidate stale object (origin set must-revalidate or proxy-revalidate)");
        if (request)
            request->flags.failOnValidationError = true;
        return STALE_MUST_REVALIDATE;
    }

    /* request-specific checks */
    if (request && !request->flags.ignoreCc) {
        HttpHdrCc *cc = request->cache_control;

        /* If the request is an IMS request, and squid is configured NOT to service this from cache
         * (either by 'refresh-ims' in the refresh pattern or 'refresh_all_ims on' globally)
         * then force a reload from the origin.
         */
        if (request->flags.ims && (R->flags.refresh_ims || Config.onoff.refresh_all_ims)) {
            // The client's no-cache header is changed into a IMS query
            debugs(22, 3, "YES: Client IMS request forcing revalidation of object (refresh-ims option)");
            return STALE_FORCED_RELOAD;
        }

#if USE_HTTP_VIOLATIONS
        /* Normally a client reload request ("Cache-Control: no-cache" or "Pragma: no-cache")
         * means we must treat this reponse as STALE and fetch a new one.
         *
         * However, some options exist to override this behaviour. For example, we might just
         * revalidate our existing response, or even just serve it up without revalidating it.
         *
         *     ---- Note on the meaning of nocache_hack -----
         *
         * The nocache_hack flag has a very specific and complex meaning:
         *
         * (a) this is a reload request ("Cache-Control: no-cache" or "Pragma: no-cache" header)
         * and (b) the configuration file either has at least one refresh_pattern with
         * ignore-reload or reload-into-ims (not necessarily the rule matching this request) or
         * the global reload_into_ims is set to on
         *
         * In other words: this is a client reload, and we might need to override
         * the default behaviour (but we might not).
         *
         * "nocache_hack" is a pretty deceptive name for such a complicated meaning.
         */
        if (request->flags.noCacheHack()) {

            if (R->flags.ignore_reload) {
                /* The client's no-cache header is ignored completely - we'll try to serve
                 * what we have (assuming it's still fresh, etc.)
                 */
                debugs(22, 3, "MAYBE: Ignoring client reload request - trying to serve from cache (ignore-reload option)");
            } else if (R->flags.reload_into_ims || Config.onoff.reload_into_ims) {
                /* The client's no-cache header is not honoured completely - we'll just try
                 * to revalidate our cached copy (IMS to origin) instead of fetching a new
                 * copy with an unconditional GET.
                 */
                debugs(22, 3, "YES: Client reload request - cheating, only revalidating with origin (reload-into-ims option)");
                return STALE_RELOAD_INTO_IMS;
            } else {
                /* The client's no-cache header is honoured - we fetch a new copy from origin */
                debugs(22, 3, "YES: Client reload request - fetching new copy from origin");
                request->flags.noCache = true;
                return STALE_FORCED_RELOAD;
            }
        }
#endif

        // Check the Cache-Control client request header
        if (NULL != cc) {

            // max-age directive
            if (cc->hasMaxAge()) {
#if USE_HTTP_VIOLATIONS
                // Ignore client "Cache-Control: max-age=0" header
                if (R->flags.ignore_reload && cc->maxAge() == 0) {
                    debugs(22, 3, "MAYBE: Ignoring client reload request - trying to serve from cache (ignore-reload option)");
                } else
#endif
                {
                    // Honour client "Cache-Control: max-age=x" header
                    if (age > cc->maxAge() || cc->maxAge() == 0) {
                        debugs(22, 3, "YES: Revalidating object - client 'Cache-Control: max-age=" << cc->maxAge() << "'");
                        return STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE;
                    }
                }
            }

            // max-stale directive
            if (cc->hasMaxStale() && staleness > -1) {
                if (cc->maxStale()==HttpHdrCc::MAX_STALE_ANY) {
                    debugs(22, 3, "NO: Client accepts a stale response of any age - 'Cache-Control: max-stale'");
                    return FRESH_REQUEST_MAX_STALE_ALL;
                } else if (staleness < cc->maxStale()) {
                    debugs(22, 3, "NO: Client accepts a stale response - 'Cache-Control: max-stale=" << cc->maxStale() << "'");
                    return FRESH_REQUEST_MAX_STALE_VALUE;
                }
            }
        }
    }

    // If the object is fresh, return the right FRESH_ code
    if (-1 == staleness) {
        debugs(22, 3, "Object isn't stale..");
        if (sf.expires) {
            debugs(22, 3, "returning FRESH_EXPIRES");
            return FRESH_EXPIRES;
        }

        assert(!sf.max);

        if (sf.lmfactor) {
            debugs(22, 3, "returning FRESH_LMFACTOR_RULE");
            return FRESH_LMFACTOR_RULE;
        }

        assert(sf.min);

        debugs(22, 3, "returning FRESH_MIN_RULE");
        return FRESH_MIN_RULE;
    }

    /*
     * At this point the response is stale, unless one of
     * the override options kicks in.
     * NOTE: max-stale config blocks the overrides.
     */
    int max_stale = (R->max_stale >= 0 ? R->max_stale : Config.maxStale);
    if ( max_stale >= 0 && staleness > max_stale) {
        debugs(22, 3, "YES: refresh_pattern max-stale=N limit from squid.conf");
        if (request)
            request->flags.failOnValidationError = true;
        return STALE_MAX_STALE;
    }

    if (sf.expires) {
#if USE_HTTP_VIOLATIONS

        if (R->flags.override_expire && age < R->min) {
            debugs(22, 3, "NO: Serving from cache - even though explicit expiry has passed, we enforce Min value (override-expire option)");
            return FRESH_OVERRIDE_EXPIRES;
        }

#endif
        return STALE_EXPIRES;
    }

    if (sf.max)
        return STALE_MAX_RULE;

    if (sf.lmfactor) {
#if USE_HTTP_VIOLATIONS
        if (R->flags.override_lastmod && age < R->min) {
            debugs(22, 3, "NO: Serving from cache - even though L-M factor says the object is stale, we enforce Min value (override-lastmod option)");
            return FRESH_OVERRIDE_LASTMOD;
        }
#endif
        debugs(22, 3, "YES: L-M factor says the object is stale'");
        return STALE_LMFACTOR_RULE;
    }

    debugs(22, 3, "returning STALE_DEFAULT");
    return STALE_DEFAULT;
}

/**
 * This is called by http.cc once it has received and parsed the origin server's
 * response headers. It uses the result as part of its algorithm to decide whether a
 * response should be cached.
 *
 * \retval true if the entry is cacheable, regardless of whether FRESH or STALE
 * \retval false if the entry is not cacheable
 *
 * TODO: this algorithm seems a bit odd and might not be quite right. Verify against HTTPbis.
 */
bool
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
    ++ refreshCounts[rcStore].total;
    ++ refreshCounts[rcStore].status[reason];

    if (reason < STALE_MUST_REVALIDATE)
        /* Does not need refresh. This is certainly cachable */
        return true;

    if (entry->lastmod < 0)
        /* Last modified is needed to do a refresh */
        return false;

    if (entry->mem_obj == NULL)
        /* no mem_obj? */
        return true;

    if (entry->getReply() == NULL)
        /* no reply? */
        return true;

    if (entry->getReply()->content_length == 0)
        /* No use refreshing (caching?) 0 byte objects */
        return false;

    /* This seems to be refreshable. Cache it */
    return true;
}

/// whether reply is stale if it is a hit
static bool
refreshIsStaleIfHit(const int reason)
{
    switch (reason) {
    case FRESH_MIN_RULE:
    case FRESH_LMFACTOR_RULE:
    case FRESH_EXPIRES:
        return false;
    default:
        return true;
    }
}

/**
 * Protocol-specific wrapper around refreshCheck() function.
 *
 * Note the reason for STALE/FRESH then return true/false respectively.
 *
 * \retval 1 if STALE
 * \retval 0 if FRESH
 */
int
refreshCheckHTTP(const StoreEntry * entry, HttpRequest * request)
{
    int reason = refreshCheck(entry, request, 0);
    ++ refreshCounts[rcHTTP].total;
    ++ refreshCounts[rcHTTP].status[reason];
    request->flags.staleIfHit = refreshIsStaleIfHit(reason);
    return (Config.onoff.offline || reason < 200) ? 0 : 1;
}

/// \see int refreshCheckHTTP(const StoreEntry * entry, HttpRequest * request)
int
refreshCheckICP(const StoreEntry * entry, HttpRequest * request)
{
    int reason = refreshCheck(entry, request, 30);
    ++ refreshCounts[rcICP].total;
    ++ refreshCounts[rcICP].status[reason];
    return (reason < 200) ? 0 : 1;
}

#if USE_HTCP
/// \see int refreshCheckHTTP(const StoreEntry * entry, HttpRequest * request)
int
refreshCheckHTCP(const StoreEntry * entry, HttpRequest * request)
{
    int reason = refreshCheck(entry, request, 10);
    ++ refreshCounts[rcHTCP].total;
    ++ refreshCounts[rcHTCP].status[reason];
    return (reason < 200) ? 0 : 1;
}

#endif

#if USE_CACHE_DIGESTS
/// \see int refreshCheckHTTP(const StoreEntry * entry, HttpRequest * request)
int
refreshCheckDigest(const StoreEntry * entry, time_t delta)
{
    int reason = refreshCheck(entry,
                              entry->mem_obj ? entry->mem_obj->request : NULL,
                              delta);
    ++ refreshCounts[rcCDigest].total;
    ++ refreshCounts[rcCDigest].status[reason];
    return (reason < 200) ? 0 : 1;
}
#endif

/**
 * Get the configured maximum caching time for objects with this URL
 * according to refresh_pattern.
 *
 * Used by http.cc when generating a upstream requests to ensure that
 * responses it is given are fresh enough to be worth caching.
 *
 * \retval pattern-max if there is a refresh_pattern matching the URL configured.
 * \retval REFRESH_DEFAULT_MAX if there are no explicit limits configured
 */
time_t
getMaxAge(const char *url)
{
    const RefreshPattern *R;
    debugs(22, 3, "getMaxAge: '" << url << "'");

    if ((R = refreshLimits(url)))
        return R->max;
    else
        return REFRESH_DEFAULT_MAX;
}

static int
refreshCountsStatsEntry(StoreEntry * sentry, struct RefreshCounts &rc, int code, const char *desc)
{
    storeAppendPrintf(sentry, "%6d\t%6.2f\t%s\n", rc.status[code], xpercent(rc.status[code], rc.total), desc);
    return rc.status[code];
}

static void
refreshCountsStats(StoreEntry * sentry, struct RefreshCounts &rc)
{
    if (!rc.total)
        return;

    storeAppendPrintf(sentry, "\n\n%s histogram:\n", rc.proto);
    storeAppendPrintf(sentry, "Count\t%%Total\tCategory\n");

    int sum = 0;
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_REQUEST_MAX_STALE_ALL, "Fresh: request max-stale wildcard");
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_REQUEST_MAX_STALE_VALUE, "Fresh: request max-stale value");
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_EXPIRES, "Fresh: expires time not reached");
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_LMFACTOR_RULE, "Fresh: refresh_pattern last-mod factor percentage");
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_MIN_RULE, "Fresh: refresh_pattern min value");
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_OVERRIDE_EXPIRES, "Fresh: refresh_pattern override-expires");
    sum += refreshCountsStatsEntry(sentry, rc, FRESH_OVERRIDE_LASTMOD, "Fresh: refresh_pattern override-lastmod");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_MUST_REVALIDATE, "Stale: response has must-revalidate");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_RELOAD_INTO_IMS, "Stale: changed reload into IMS");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_FORCED_RELOAD, "Stale: request has no-cache directive");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_EXCEEDS_REQUEST_MAX_AGE_VALUE, "Stale: age exceeds request max-age value");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_EXPIRES, "Stale: expires time reached");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_MAX_RULE, "Stale: refresh_pattern max age rule");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_LMFACTOR_RULE, "Stale: refresh_pattern last-mod factor percentage");
    sum += refreshCountsStatsEntry(sentry, rc, STALE_DEFAULT, "Stale: by default");

    storeAppendPrintf(sentry, "%6d\t%6.2f\tTOTAL\n", rc.total, xpercent(rc.total, sum));
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
        refreshCountsStats(sentry, refreshCounts[i]);
}

static void
refreshRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("refresh", "Refresh Algorithm Statistics", refreshStats, 0, 1);
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

    refreshRegisterWithCacheManager();
}

