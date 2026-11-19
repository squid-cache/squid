/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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

#include <algorithm>
#include <cmath>

FadingCounter::FadingCounter(): horizon(-1), precision(10), delta(-1),
    lastTime(0), total(0)
{
    counters.reserve(precision);
    while (counters.size() < static_cast<unsigned int>(precision))
        counters.push_back(0);
}

void FadingCounter::clear()
{
    for (int i = 0; i < precision; ++i)
        counters[i] = 0;
    lastTime = current_dtime;
    total = 0;
}

void FadingCounter::configure(double newHorizon)
{
    if (fabs(newHorizon - horizon) >= 1e-3) { // diff exceeds one millisecond
        clear(); // for simplicity
        horizon = newHorizon;
        delta = horizon / precision; // may become negative or zero
    }
}

int FadingCounter::count(int howMany)
{
    Must(howMany >= 0);

    if (delta < 0)
        return total += howMany; // forget nothing

    if (horizon < 1e-3) // (e.g., zero)
        return howMany; // remember nothing

    // Use the phase within a horizon to avoid converting large timestamps
    // to integer slot numbers.
    const auto phase = fmod(current_dtime, horizon);
    const auto slotAt = [this](const double offset) {
        return std::min(static_cast<int>(offset / delta), precision - 1);
    };
    const auto curSlot = slotAt(phase);
    if (current_dtime - lastTime >= horizon || current_dtime < lastTime) {
        clear(); // forget all values
    } else {
        // Expire each slot crossed, even when updates are less than delta apart.
        const auto lastPhase = fmod(lastTime, horizon);
        const auto lastSlot = slotAt(lastPhase);
        const auto staleSlots = curSlot - lastSlot + (phase < lastPhase ? precision : 0);
        for (int i = 0, s = lastSlot + 1; i < staleSlots; ++i, ++s) {
            const int idx = s % precision;
            total -= counters[idx];
            counters[idx] = 0;
            Must(total >= 0);
        }
    }

    // apply new information
    lastTime = current_dtime;
    counters[curSlot] += howMany;
    total += howMany;
    Must(total >= 0);

    return total;
}

