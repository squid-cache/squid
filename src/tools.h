/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Misc Functions */

#ifndef SQUID_TOOLS_H_
#define SQUID_TOOLS_H_

#include "sbuf/SBuf.h"
#include "typedefs.h"

class MemBuf;

extern int DebugSignal;

/// The Squid -n parameter service name.
/// Default is APP_SHORTNAME ('squid').
extern SBuf service_name;

void parseEtcHosts(void);
int getMyPort(void);
void setUmask(mode_t mask);
void strwordquote(MemBuf * mb, const char *str);

class Packable;

/* a common objPackInto interface; used by debugObj */
typedef void (*ObjPackMethod) (void *obj, Packable * p);

/* packs, then prints an object using debugs() */
void debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm);

/// callback type for signal handlers
typedef void SIGHDLR(int sig);

const char *getMyHostname(void);
const char *uniqueHostname(void);

void death(int sig);
void sigusr2_handle(int sig);
void sig_child(int sig);
void sig_shutdown(int sig); ///< handles shutdown notifications from kids
void leave_suid(void);
void enter_suid(void);
void no_suid(void);
void setMaxFD(void);
void setSystemLimits(void);
void squid_signal(int sig, SIGHDLR *, int flags);
void keepCapabilities(void);
void BroadcastSignalIfAny(int& sig);

/// whether the current process is the parent of all other Squid processes
bool IamMasterProcess();
/**
 *   whether the current process is dedicated to doing things that only
 *   a single process should do, such as PID file maintenance and WCCP
 */
bool IamPrimaryProcess();
/// whether the current process coordinates worker processes
bool IamCoordinatorProcess();
/// whether the current process handles HTTP transactions and such
bool IamWorkerProcess();
/// whether the current process is dedicated to managing a cache_dir
bool IamDiskProcess();
/// Whether we are running in daemon mode
bool InDaemonMode(); // try using specific Iam*() checks above first
/// Whether there should be more than one worker process running
bool UsingSmp(); // try using specific Iam*() checks above first
/// number of Kid processes as defined in src/ipc/Kid.h
int NumberOfKids();
/// a string describing this process roles such as worker or coordinator
SBuf ProcessRoles();

void debug_trap(const char *);

void logsFlush(void);

void squid_getrusage(struct rusage *r);
double rusage_cputime(struct rusage *r);
int rusage_maxrss(struct rusage *r);
int rusage_pagefaults(struct rusage *r);
void releaseServerSockets(void);
void PrintRusage(void);
void dumpMallocStats(void);

#if _SQUID_NEXT_
typedef union wait PidStatus;
#else
typedef int PidStatus;
#endif

/**
 * Compatibility wrapper function for waitpid
 * \pid the pid of child process to wait for.
 * \param status the exit status returned by waitpid
 * \param flags WNOHANG or 0
 */
pid_t WaitForOnePid(pid_t pid, PidStatus &status, int flags);

/**
 * Wait for state changes in any of the kid processes.
 * Equivalent to waitpid(-1, ...) system call
 * \param status the exit status returned by waitpid
 * \param flags WNOHANG or 0
 */
inline pid_t WaitForAnyPid(PidStatus &status, int flags)
{
    return WaitForOnePid(-1, status, flags);
}

#if _SQUID_WINDOWS_
/// xstrerror(errno) equivalent for Windows errors returned by GetLastError()
SBuf WindowsErrorMessage(DWORD errorId);
#endif // _SQUID_WINDOWS_

#endif /* SQUID_TOOLS_H_ */

