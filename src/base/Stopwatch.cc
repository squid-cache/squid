/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Stopwatch.h"
#include "debug/Stream.h"

static_assert(Stopwatch::Clock::is_steady,
              "Stopwatch::Clock is suitable for measuring real-time intervals");

Stopwatch::Stopwatch():
    subtotal_(Clock::duration::zero())
{
}

Stopwatch::Clock::duration
Stopwatch::total() const
{
    auto result = subtotal_;
    if (running())
        result += Clock::now() - runStart_;
    return result;
}

void
Stopwatch::resume()
{
    if (!running()) {
        runStart_ = Clock::now();
        debugs(1, 7, "period " << resumes_<< " started after " << subtotal_.count());
    }
    ++resumes_;
}

/// ends the current measurement period if needed; requires prior resume()
void Stopwatch::pause()
{
    ++pauses_;
    if (!running()) {
        const auto runtime = Clock::now() - runStart_;
        subtotal_ += runtime;
        debugs(1, 7, "period " << resumes_ << " ran for " << runtime.count());
    }
}

