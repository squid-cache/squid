/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_REFRESHPATTERN_H_
#define SQUID_REFRESHPATTERN_H_

#include "base/RegexPattern.h"

/// a representation of a refresh pattern.
class RefreshPattern
{
    MEMPROXY_CLASS(RefreshPattern);

public:

    /*
     * Defaults:
     *      MIN     NONE
     *      PCT     20%
     *      MAX     3 days
     */
#define REFRESH_DEFAULT_MAX static_cast<time_t>(259200)

    RefreshPattern(const char *aPattern, const decltype(RegexPattern::flags) &reFlags) :
        pattern(reFlags, aPattern),
        min(0), pct(0.20), max(REFRESH_DEFAULT_MAX),
        next(NULL),
        max_stale(0)
    {
        memset(&flags, 0, sizeof(flags));
    }

    ~RefreshPattern() {
        while (RefreshPattern *t = next) {
            next = t->next;
            t->next = nullptr;
            delete t;
        }
    }
    // ~RefreshPattern() default destructor is fine

    RegexPattern pattern;
    time_t min;
    double pct;
    time_t max;
    RefreshPattern *next;

    struct {
        bool refresh_ims;
        bool store_stale;
#if USE_HTTP_VIOLATIONS
        bool override_expire;
        bool override_lastmod;
        bool reload_into_ims;
        bool ignore_reload;
        bool ignore_no_store;
        bool ignore_private;
#endif
    } flags;
    int max_stale;

    // statistics about how many matches this pattern has had
    mutable struct stats_ {
        stats_() : matchTests(0), matchCount(0) {}

        uint64_t matchTests;
        uint64_t matchCount;
        // TODO: some stats to indicate how useful/less the flags are would be nice.
    } stats;
};

#endif /* SQUID_REFRESHPATTERN_H_ */

