/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "FadingCounter.h"
#include "SquidTime.h"

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

    const double deltas = (current_dtime - lastTime) / delta;
    if (deltas >= precision || current_dtime < lastTime) {
        clear(); // forget all values
    } else {
        // forget stale values, if any
        // fmod() or "current_dtime/delta" will overflow int for small deltas
        const int lastSlot = static_cast<int>(fmod(lastTime, horizon) / delta);
        const int staleSlots = static_cast<int>(deltas);
        for (int i = 0, s = lastSlot + 1; i < staleSlots; ++i, ++s) {
            const int idx = s % precision;
            total -= counters[idx];
            counters[idx] = 0;
            Must(total >= 0);
        }
    }

    // apply new information
    lastTime = current_dtime;
    const int curSlot = static_cast<int>(fmod(lastTime, horizon) / delta);
    counters[curSlot % precision] += howMany;
    total += howMany;
    Must(total >= 0);

    return total;
}

