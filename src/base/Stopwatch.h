/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_STOPWATCH_H
#define SQUID_SRC_BASE_STOPWATCH_H

#include <chrono>
#include <cstdint>

/// Quickly accumulates related real-time (a.k.a. "physical time" or "wall
/// clock") periods. Continues to run if the caller is blocked on a system call.
/// Usually suitable for measuring CPU overheads of non-sleeping code sequences.
class Stopwatch
{
public:
    // std::clock() is not precise enough and raises (minor) overflow concerns;
    // clock_gettime(CLOCK_PROCESS_CPUTIME_ID) may not be portable, and both may
    // include CPU ticks accumulated by [AUFS] threads. When the code does
    // not sleep (i.e. always does something), wall clock time is better.

    // Do not be tempted by std::high_resolution_clock spelling! That clock has
    // unpredictable properties. It may not be steady (i.e. !is_steady). Its use
    // is discouraged[1,3]. In most implementations, the steady_clock resolution
    // is just as high[1,2,3].
    // [1]: https://en.cppreference.com/w/cpp/chrono/high_resolution_clock
    // [2]: https://howardhinnant.github.io/clock_survey.html
    // [3]: https://stackoverflow.com/questions/38252022/does-standard-c11-guarantee-that-high-resolution-clock-measure-real-time-non

    /// the underlying time measuring mechanism
    using Clock = std::chrono::steady_clock;

    Stopwatch();

    /// whether we are currently measuring time (i.e. between resume() and pause())
    bool running() const { return resumes_ > pauses_; }

    /// whether we ever measured time (i.e. resume() has been called)
    bool ran() const { return resumes_ > 0; }

    /// the sum of all measurement period durations (or zero)
    /// includes the current measurement period, if any
    Clock::duration total() const;

    /// (re)starts or continues the current measurement period; each resume()
    /// call must be paired with a dedicated future pause() call
    void resume();

    /// ends the current measurement period if needed; each pause() call
    /// requires a prior dedicated resume() call
    void pause();

private:
    Clock::time_point runStart_; ///< when the current period was initiated

    Clock::duration subtotal_; ///< the sum of all _finished_ periods

    uint64_t resumes_ = 0; ///< the total number of resume() calls
    uint64_t pauses_ = 0; ///< the total number of pause() calls
};

#endif /* SQUID_SRC_BASE_STOPWATCH_H */

