/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "FadingCounter.h"
#include "time/gadgets.h"

#include <cmath>

FadingCounter::FadingCounter() : counters(Precision,0)
{
}

void
FadingCounter::clear()
{
    std::fill(counters.begin(), counters.end(), 0);
    lastTime = current_dtime;
    total = 0;
}

void
FadingCounter::configure(const time_t newHorizon)
{
    if (newHorizon != horizon_) {
        clear(); // for simplicity
        horizon_ = newHorizon;
        delta = horizon_ / Precision; // may become zero
    }
}

uint64_t
FadingCounter::count(uint64_t howMany)
{
    if (horizon() < 0)
        return total += howMany; // forget nothing

    if (horizon() == 0)
        return howMany; // remember nothing

    const double deltas = (current_dtime - lastTime) / delta;
    if (deltas >= Precision || current_dtime < lastTime) {
        clear(); // forget all values
    } else {
        // forget stale values, if any
        // fmod() or "current_dtime/delta" will overflow int for small deltas
        const auto lastSlot = static_cast<int>(fmod(lastTime, horizon()) / delta);
        const int staleSlots = static_cast<int>(deltas);
        for (int i = 0, s = lastSlot + 1; i < staleSlots; ++i, ++s) {
            const auto idx = s % Precision;
            total -= counters[idx];
            counters[idx] = 0;
        }
    }

    // apply new information
    lastTime = current_dtime;
    const auto curSlot = static_cast<int>(fmod(lastTime, horizon()) / delta);
    counters[curSlot % Precision] += howMany;
    total += howMany;

    return total;
}

