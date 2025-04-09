/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FADINGCOUNTER_H
#define SQUID_SRC_FADINGCOUNTER_H

#include <array>
#include <chrono>

using namespace std::chrono_literals;

/// Counts events, forgetting old ones. Useful for "3 errors/minute" limits.
class FadingCounter
{
public:
    using Horizon = std::chrono::seconds;

    /**
     * Special values:
     * \li Horizon::zero() - Remember nothing
     * \li Horizon::max()  - Forget nothing (the default)
     *
     * new value triggers clear(), setting the existing value does not.
     */
    void configure(const Horizon &);

    void clear(); ///< forgets all events

    uint64_t count(uint64_t howMany); ///< count fresh, return #events remembered
    auto remembered() const { return total; } ///< possibly stale #events

    /// read-only memory horizon; older events are forgotten
    Horizon horizon() const { return horizon_; }

private:
    Horizon horizon_ = Horizon::max();
    double delta = -1; ///< sub-interval duration = horizon/precision

    double lastTime = 0.0; ///< time of the last update
    std::array<int, 10> counters = {}; ///< events per delta (possibly stale)
    uint64_t total = 0; ///< number of remembered events (possibly stale)
};

#endif /* SQUID_SRC_FADINGCOUNTER_H */

