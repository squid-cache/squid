/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_KIDS_H
#define SQUID_IPC_KIDS_H

#include "ipc/Kid.h"

#include <vector>

/// a collection of kids
class Kids
{
public:
    Kids ();

private:
    Kids (const Kids&); ///< not implemented
    Kids& operator= (const Kids&); ///< not implemented

public:
    /// initialize all kid records based on Config
    void init();

    /// returns kid by pid
    Kid* find(pid_t pid);

    /// returns the kid by index, useful for kids iteration
    Kid& get(size_t i);

    /// whether all kids are hopeless
    bool allHopeless() const;

    /// forgets all failures in all kids
    void forgetAllFailures();

    /// forgets all failures in hopeless kids that were dead for a long time
    /// \returns seconds till the next check (zero if there are no hopeless kids left)
    time_t forgetOldFailures();

    /// whether all kids called exited happy
    bool allExitedHappy() const;

    /// whether some kids died from a given signal
    bool someSignaled(const int sgnl) const;

    /// whether some kids are running
    bool someRunning() const;

    /// whether some kids should be restarted by master
    bool shouldRestartSome() const;

    /// returns the number of kids
    size_t count() const;

private:
    std::vector<Kid> storage;
};

extern Kids TheKids; ///< All kids being maintained

extern SBuf TheKidName; ///< current Squid process name (e.g., "squid-coord")

#endif /* SQUID_IPC_KIDS_H */

