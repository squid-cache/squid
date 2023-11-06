/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FADING_COUNTER_H
#define SQUID_FADING_COUNTER_H

#include <vector>

/// Counts events, forgetting old ones. Useful for "3 errors/minute" limits.
class FadingCounter
{
public:
    FadingCounter();

    /// 0=remember nothing; -1=forget nothing; new value triggers clear()
    void configure(double horizonSeconds);

    void clear(); ///< forgets all events

    int count(int howMany); ///< count fresh, return #events remembered
    int remembered() const { return total; } ///< possibly stale #events

    /// read-only memory horizon in seconds; older events are forgotten
    double horizon;

private:
    const int precision; ///< #counting slots, controls measur. accuracy
    double delta; ///< sub-interval duration = horizon/precision

    double lastTime; ///< time of the last update
    std::vector<int> counters; ///< events per delta (possibly stale)
    int total; ///< number of remembered events (possibly stale)
};

#endif /* SQUID_FADING_COUNTER_H */

