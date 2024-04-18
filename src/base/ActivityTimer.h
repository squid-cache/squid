/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ACTIVITYTIMER_H
#define SQUID_SRC_BASE_ACTIVITYTIMER_H

#include "base/Stopwatch.h"

/// Eliminates excessive Stopwatch resume() and pause() calls in a task with
/// multiple code locations that resume (or pause) a stopwatch. Ideally, there
/// would be just one such location per action (e.g., constructor resumes while
/// destructor pauses), but current code idiosyncrasies necessitate this state.
class ActivityTimer
{
public:
    // TODO: Call timer.resume() here if possible, eliminating `resumed` and
    // adjusting class description to be exclusively about pause().
    ActivityTimer(Stopwatch &w): timer(w) {}

    ~ActivityTimer() { stop(); }

    void start()
    {
        if (!resumed) {
            timer.resume();
            resumed = true;
        }
    }

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
    bool resumed = false;
    bool paused = false;
};

#endif /* SQUID_SRC_BASE_ACTIVITYTIMER_H */

