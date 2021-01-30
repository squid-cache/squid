/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
// XXX: need src/ to avoid clashes with ip/tools.h in testIpAddress
#include "src/tools.h"

#define STUB_API "tools.cc"
#include "tests/STUB.h"

int DebugSignal = -1;
SBuf service_name(APP_SHORTNAME);
void releaseServerSockets(void) STUB_NOP
char * dead_msg(void) STUB_RETVAL(NULL)
void mail_warranty(void) STUB
void dumpMallocStats(void) STUB
void squid_getrusage(struct rusage *r) STUB
double rusage_cputime(struct rusage *r) STUB_RETVAL(0)
int rusage_maxrss(struct rusage *r) STUB_RETVAL(0)
int rusage_pagefaults(struct rusage *r) STUB_RETVAL(0)
void PrintRusage(void) STUB
void death(int sig) STUB
void BroadcastSignalIfAny(int& sig) STUB
void sigusr2_handle(int sig) STUB
void debug_trap(const char *message) STUB
void sig_child(int sig) STUB
const char * getMyHostname(void) STUB_RETVAL(NULL)
const char * uniqueHostname(void) STUB_RETVAL(NULL)
void leave_suid(void) STUB_NOP
void enter_suid(void) STUB
void no_suid(void) STUB

bool
IamMasterProcess()
{
    //std::cerr << STUB_API << " IamMasterProcess() Not implemented\n";
    // Since most tests run as a single process, this is the best default.
    // TODO: If some test case uses multiple processes and cares about
    // its role, we may need to parameterize or remove this stub.
    return true;
}

bool
IamWorkerProcess()
{
    //std::cerr << STUB_API << " IamWorkerProcess() Not implemented\n";
    return true;
}

bool IamDiskProcess() STUB_RETVAL_NOP(false)
bool InDaemonMode() STUB_RETVAL_NOP(false)
bool UsingSmp() STUB_RETVAL_NOP(false)
bool IamCoordinatorProcess() STUB_RETVAL(false)
bool IamPrimaryProcess() STUB_RETVAL(false)
int NumberOfKids() STUB_RETVAL(0)

//not actually needed in the Stub, causes dependency on SBuf
//SBuf ProcessRoles() STUB_RETVAL(SBuf())
void setMaxFD(void) STUB
void setSystemLimits(void) STUB
void squid_signal(int sig, SIGHDLR * func, int flags) STUB
void logsFlush(void) STUB
void debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm) STUB
void parseEtcHosts(void) STUB
int getMyPort(void) STUB_RETVAL(0)
void setUmask(mode_t mask) STUB
void strwordquote(MemBuf * mb, const char *str) STUB
void keepCapabilities(void) STUB
void restoreCapabilities(bool keep) STUB
pid_t WaitForOnePid(pid_t pid, PidStatus &status, int flags) STUB_RETVAL(0)

#if _SQUID_WINDOWS_
SBuf WindowsErrorMessage(DWORD) STUB_RETVAL(SBuf())
#endif // _SQUID_WINDOWS_

