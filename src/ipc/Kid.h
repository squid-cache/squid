/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

    Kid(const char *role, const int id);

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

    /// forgets all past failures, ensuring that we are not hopeless()
    void forgetFailures() { badFailures = 0; }

    /// \returns the time since process termination
    time_t deathDuration() const;

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

    /// \returns kid's role and ID formatted for use as a process name
    SBuf processName() const;

    /// \returns kid's role and ID summary; usable as a --kid parameter value
    SBuf gist() const;

private:
    void reportStopped() const;

    // Information preserved across restarts
    SBuf processRole;
    int processId = 0;
    int badFailures = 0; ///< number of "repeated frequent" failures

    // Information specific to a running or stopped kid
    pid_t  pid = -1; ///< current (for a running kid) or last (for stopped kid) PID
    time_t startTime = 0; ///< last start time
    time_t stopTime = 0; ///< last termination time
    bool isRunning = false; ///< whether the kid is assumed to be alive
    PidStatus status = 0; ///< exit status of a stopped kid
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

