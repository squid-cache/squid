/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FADINGCOUNTER_H
#define SQUID_SRC_FADINGCOUNTER_H

#include <vector>

/// Counts events, forgetting old ones. Useful for "3 errors/minute" limits.
class FadingCounter
{
public:
    FadingCounter();

    /// 0=remember nothing; -1=forget nothing; new value triggers clear()
    void configure(const time_t horizonSeconds);

    void clear(); ///< forgets all events

    uint64_t count(uint64_t howMany); ///< count fresh, return #events remembered
    auto remembered() const { return total; } ///< possibly stale #events

    /// read-only memory horizon in seconds; older events are forgotten
    time_t horizon() const { return horizon_; }

private:
    static const size_t Precision = 10; ///< #counting slots, controls measur. accuracy

    time_t horizon_ = -1;
    double delta = -1; ///< sub-interval duration = horizon/precision

    double lastTime = 0.0; ///< time of the last update
    std::vector<int> counters; ///< events per delta (possibly stale)
    uint64_t total = 0; ///< number of remembered events (possibly stale)
};

#endif /* SQUID_SRC_FADINGCOUNTER_H */

