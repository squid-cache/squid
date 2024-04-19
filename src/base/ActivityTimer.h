/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ACTIVITYTIMER_H
#define SQUID_SRC_BASE_ACTIVITYTIMER_H

#include "base/Stopwatch.h"

/// Eliminates excessive Stopwatch pause() calls in a task with
/// multiple code locations that pause a stopwatch. Ideally, there
/// would be just one such location (e.g., a destructor),
/// but current code idiosyncrasies necessitate this state.
class ActivityTimer
{
public:
    ActivityTimer(Stopwatch &w): timer(w) { timer.resume(); }

    ~ActivityTimer() { stop(); }

    void stop()
    {
        if (!paused) {
            timer.pause();
            paused = true;
        }
    }

private:
    Stopwatch &timer;

    // Do not be tempted to rely on timer.ran(): We are eliminating excessive
    // calls within a single task (e.g., an AsyncJob) while the timer (and its
    // ran() state) may be shared/affected by multiple concurrent tasks.
    bool paused = false;
};

#endif /* SQUID_SRC_BASE_ACTIVITYTIMER_H */

