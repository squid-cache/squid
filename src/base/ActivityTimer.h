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

/// Eliminates excessive Stopwatch pause() calls in a task with multiple code
/// locations that pause a stopwatch. Ideally, there would be just one such
/// location (e.g., a task class destructor), but current code idiosyncrasies
/// necessitate this state.
template <class Owner, class Location>
class ActivityTimer
{
public:
    ActivityTimer(const Owner &o, const Location &l): owner(o), location(l) { timer().resume(); }

    ~ActivityTimer() { stop(); }

    void stop()
    {
        if (!stopped) {
            timer().pause();
            stopped = true;
        }
    }

private:
    /// extracts Stopwatch from the configured location
    Stopwatch &timer() { return owner->*location; }

    /// Stopwatch owner; this is usually a strong pointer
    Owner owner;

    /// The address of a managed Stopwatch within its Owner. This is usually a
    /// pointer to Owner data member.
    Location location;

    // We cannot rely on timer().ran(): This class eliminates excessive calls
    // within a single task (e.g., an AsyncJob) while the timer (and its ran()
    // state) may be shared/affected by multiple concurrent tasks.
    /// Whether the task is done participating in the managed activity.
    bool stopped = false;
};

#endif /* SQUID_SRC_BASE_ACTIVITYTIMER_H */

