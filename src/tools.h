/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Misc Functions */

#ifndef SQUID_TOOLS_H_
#define SQUID_TOOLS_H_

#include "Packer.h"
#include "SBuf.h"
#include "SquidString.h"
#include "typedefs.h"

class MemBuf;

extern int DebugSignal;

/// The Squid -n parameter service name.
/// Default is APP_SHORTNAME ('squid').
extern SBuf service_name;

void kb_incr(kb_t *, size_t);
void parseEtcHosts(void);
int getMyPort(void);
void setUmask(mode_t mask);
void strwordquote(MemBuf * mb, const char *str);

/* packs, then prints an object using debugs() */
void debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm);

const char *getMyHostname(void);
const char *uniqueHostname(void);

void death(int sig);
void sigusr2_handle(int sig);
void sig_child(int sig);
void sig_shutdown(int sig); ///< handles shutdown notifications from kids
void leave_suid(void);
void enter_suid(void);
void no_suid(void);
void writePidFile(void);
void setMaxFD(void);
void setSystemLimits(void);
void squid_signal(int sig, SIGHDLR *, int flags);
pid_t readPidFile(void);
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
String ProcessRoles();

void debug_trap(const char *);

void logsFlush(void);

void squid_getrusage(struct rusage *r);
double rusage_cputime(struct rusage *r);
int rusage_maxrss(struct rusage *r);
int rusage_pagefaults(struct rusage *r);
void releaseServerSockets(void);
void PrintRusage(void);
void dumpMallocStats(void);

#endif /* SQUID_TOOLS_H_ */

