/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_KID_H
#define SQUID_IPC_KID_H

#include "SquidString.h"
#include "tools.h"

/// Squid child, including current forked process info and
/// info persistent across restarts
class Kid
{
public:

    /// keep restarting until the number of bad failures exceed this limit
    enum { badFailureLimit = 4 };

    /// slower start failures are not "frequent enough" to be counted as "bad"
    enum { fastFailureTimeLimit = 10 }; // seconds

public:
    Kid();

    Kid(const String& kid_name);

    /// called when this kid got started, records PID
    void start(pid_t cpid);

    /// called when kid terminates, sets exiting status
    void stop(PidStatus const exitStatus);

    /// returns true if tracking of kid is stopped
    bool running() const;

    /// returns true if master should restart this kid
    bool shouldRestart() const;

    /// returns current pid for a running kid and last pid for a stopped kid
    pid_t getPid() const;

    /// whether the failures are "repeated and frequent"
    bool hopeless() const;

    /// returns true if the process terminated normally
    bool calledExit() const;

    /// returns the exit status of the process
    int exitStatus() const;

    /// whether the process exited with a given exit status code
    bool calledExit(int code) const;

    /// whether the process exited with code 0
    bool exitedHappy() const;

    /// returns true if the kid was terminated by a signal
    bool signaled() const;

    /// returns the number of the signal that caused the kid to terminate
    int termSignal() const;

    /// whether the process was terminated by a given signal
    bool signaled(int sgnl) const;

    /// returns kid name
    const String& name() const;

private:
    // Information preserved across restarts
    String theName; ///< process name
    int badFailures; ///< number of "repeated frequent" failures

    // Information specific to a running or stopped kid
    pid_t  pid; ///< current (for a running kid) or last (for stopped kid) PID
    time_t startTime; ///< last start time
    bool   isRunning; ///< whether the kid is assumed to be alive
    PidStatus status; ///< exit status of a stopped kid
};

// TODO: processes may not be kids; is there a better place to put this?

/// process kinds
typedef enum {
    pkOther  = 0, ///< we do not know or do not care
    pkCoordinator = 1, ///< manages all other kids
    pkWorker = 2, ///< general-purpose worker bee
    pkDisker = 4, ///< cache_dir manager
    pkHelper = 8  ///< general-purpose helper child
} ProcessKind;

/// ProcessKind for the current process
extern int TheProcessKind;

#endif /* SQUID_IPC_KID_H */

