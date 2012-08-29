/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_PROTOS_H
#define SQUID_PROTOS_H

/* included for routines that have not moved out to their proper homes
 * yet.
 */
#include "Packer.h"
/* for routines still in this file that take CacheManager parameters */
#include "ip/Address.h"
/* for parameters that still need these */
#include "enums.h"
/* some parameters stil need this */
#include "wordlist.h"
#include "anyp/ProtocolType.h"
#include "Debug.h"
#include "HttpHeader.h"
#include "HttpStatusCode.h"
#include "lookup_t.h"

class HttpRequestMethod;
#if USE_DELAY_POOLS
class ClientInfo;
#endif

class FwdState;

class HttpRequest;
class HttpReply;


#if SQUID_SNMP
SQUIDCEXTERN PF snmpHandleUdp;
SQUIDCEXTERN void snmpInit(void);
SQUIDCEXTERN void snmpOpenPorts(void);
SQUIDCEXTERN void snmpClosePorts(void);
SQUIDCEXTERN const char * snmpDebugOid(oid * Name, snint Len, MemBuf &outbuf);

SQUIDCEXTERN void addr2oid(Ip::Address &addr, oid *Dest);
SQUIDCEXTERN void oid2addr(oid *Dest, Ip::Address &addr, u_int code);

SQUIDCEXTERN Ip::Address *client_entry(Ip::Address *current);
extern variable_list *snmp_basicFn(variable_list *, snint *);
extern variable_list *snmp_confFn(variable_list *, snint *);
extern variable_list *snmp_sysFn(variable_list *, snint *);
extern variable_list *snmp_prfSysFn(variable_list *, snint *);
extern variable_list *snmp_prfProtoFn(variable_list *, snint *);
extern variable_list *snmp_prfPeerFn(variable_list *, snint *);
extern variable_list *snmp_netIpFn(variable_list *, snint *);
extern variable_list *snmp_netFqdnFn(variable_list *, snint *);
extern variable_list *snmp_netDnsFn(variable_list *, snint *);
extern variable_list *snmp_meshPtblFn(variable_list *, snint *);
extern variable_list *snmp_meshCtblFn(variable_list *, snint *);
#endif /* SQUID_SNMP */


#include "ipcache.h"
extern int mcastSetTtl(int, int);
extern IPH mcastJoinGroups;

#include "comm/forward.h"
extern void getOutgoingAddress(HttpRequest * request, Comm::ConnectionPointer conn);
extern Ip::Address getOutgoingAddr(HttpRequest * request, struct peer *dst_peer);

SQUIDCEXTERN void urnStart(HttpRequest *, StoreEntry *);

SQUIDCEXTERN void redirectInit(void);
SQUIDCEXTERN void redirectShutdown(void);

extern void shut_down(int);
extern void rotate_logs(int);
extern void reconfigure(int);

extern void start_announce(void *unused);
extern void waisStart(FwdState *);

/* ----------------------------------------------------------------- */

/* repl_modules.c */
extern void storeReplSetup(void);

/*
 * store_log.c
 */
extern void storeLog(int tag, const StoreEntry * e);
extern void storeLogRotate(void);
extern void storeLogClose(void);
extern void storeLogOpen(void);

/*
 * store_digest.c
 */
extern void storeDigestInit(void);
extern void storeDigestNoteStoreReady(void);
extern void storeDigestScheduleRebuild(void);
extern void storeDigestDel(const StoreEntry * entry);
extern void storeDigestReport(StoreEntry *);

/*
 * store_rebuild.c
 */
SQUIDCEXTERN void storeRebuildStart(void);

SQUIDCEXTERN void storeRebuildComplete(struct _store_rebuild_data *);
SQUIDCEXTERN void storeRebuildProgress(int sd_index, int total, int sofar);

/// loads entry from disk; fills supplied memory buffer on success
extern bool storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, struct _store_rebuild_data &counts);
/// parses entry buffer and validates entry metadata; fills e on success
extern bool storeRebuildParseEntry(MemBuf &buf, StoreEntry &e, cache_key *key, struct _store_rebuild_data &counts, uint64_t expectedSize);
/// checks whether the loaded entry should be kept; updates counters
extern bool storeRebuildKeepEntry(const StoreEntry &e, const cache_key *key, struct _store_rebuild_data &counts);

/*
 * store_swapin.c
 */
class store_client;
extern void storeSwapInStart(store_client *);

/*
 * store_client.c
 */
SQUIDCEXTERN store_client *storeClientListAdd(StoreEntry * e, void *data);
SQUIDCEXTERN int storeClientCopyPending(store_client *, StoreEntry * e, void *data);
SQUIDCEXTERN int storeUnregister(store_client * sc, StoreEntry * e, void *data)
;
SQUIDCEXTERN int storePendingNClients(const StoreEntry * e);
SQUIDCEXTERN int storeClientIsThisAClient(store_client * sc, void *someClient);

SQUIDCEXTERN const char *getMyHostname(void);
SQUIDCEXTERN const char *uniqueHostname(void);
SQUIDCEXTERN void safeunlink(const char *path, int quiet);

#include "fatal.h"
extern void death(int sig);
extern void sigusr2_handle(int sig);
extern void sig_child(int sig);
extern void sig_shutdown(int sig); ///< handles shutdown notifications from kids
SQUIDCEXTERN void leave_suid(void);
SQUIDCEXTERN void enter_suid(void);
SQUIDCEXTERN void no_suid(void);
SQUIDCEXTERN void writePidFile(void);
SQUIDCEXTERN void setSocketShutdownLifetimes(int);
SQUIDCEXTERN void setMaxFD(void);
SQUIDCEXTERN void setSystemLimits(void);
extern void squid_signal(int sig, SIGHDLR *, int flags);
SQUIDCEXTERN pid_t readPidFile(void);
SQUIDCEXTERN void keepCapabilities(void);
SQUIDCEXTERN void BroadcastSignalIfAny(int& sig);
/// whether the current process is the parent of all other Squid processes
SQUIDCEXTERN bool IamMasterProcess();
/**
    whether the current process is dedicated to doing things that only
    a single process should do, such as PID file maintenance and WCCP
*/
SQUIDCEXTERN bool IamPrimaryProcess();
/// whether the current process coordinates worker processes
SQUIDCEXTERN bool IamCoordinatorProcess();
/// whether the current process handles HTTP transactions and such
SQUIDCEXTERN bool IamWorkerProcess();
/// whether the current process is dedicated to managing a cache_dir
extern bool IamDiskProcess();
/// Whether we are running in daemon mode
SQUIDCEXTERN bool InDaemonMode(); // try using specific Iam*() checks above first
/// Whether there should be more than one worker process running
SQUIDCEXTERN bool UsingSmp(); // try using specific Iam*() checks above first
/// number of Kid processes as defined in src/ipc/Kid.h
SQUIDCEXTERN int NumberOfKids();
/// a string describing this process roles such as worker or coordinator
extern String ProcessRoles();
SQUIDCEXTERN int DebugSignal;

/* AYJ debugs function to show locations being reset with memset() */
SQUIDCEXTERN void *xmemset(void *dst, int, size_t);

SQUIDCEXTERN void debug_trap(const char *);
SQUIDCEXTERN void logsFlush(void);
SQUIDCEXTERN const char *checkNullString(const char *p);

SQUIDCEXTERN void squid_getrusage(struct rusage *r);

SQUIDCEXTERN double rusage_cputime(struct rusage *r);

SQUIDCEXTERN int rusage_maxrss(struct rusage *r);

SQUIDCEXTERN int rusage_pagefaults(struct rusage *r);
SQUIDCEXTERN void releaseServerSockets(void);
SQUIDCEXTERN void PrintRusage(void);
SQUIDCEXTERN void dumpMallocStats(void);

#if USE_UNLINKD
SQUIDCEXTERN bool unlinkdNeeded(void);
SQUIDCEXTERN void unlinkdInit(void);
SQUIDCEXTERN void unlinkdClose(void);
SQUIDCEXTERN void unlinkdUnlink(const char *);
#endif

SQUIDCEXTERN peer_t parseNeighborType(const char *s);

SQUIDCEXTERN int stringHasWhitespace(const char *); //String.cc
SQUIDCEXTERN int stringHasCntl(const char *); //String.cc
SQUIDCEXTERN void linklistPush(link_list **, void *); //list.cc
SQUIDCEXTERN void *linklistShift(link_list **); //list.cc
SQUIDCEXTERN int xrename(const char *from, const char *to); //disk.cc
extern int isPowTen(int); //int.cc

SQUIDCEXTERN char *strwordtok(char *buf, char **t); //String.cc

/*
 * ipc.c
 */
SQUIDCEXTERN pid_t ipcCreate(int type,
                             const char *prog,
                             const char *const args[],
                             const char *name,
                             Ip::Address &local_addr,
                             int *rfd,
                             int *wfd,
                             void **hIpc);

/*
 * prototypes for system functions missing from system includes
 */

#if _SQUID_SOLARIS_

SQUIDCEXTERN int getrusage(int, struct rusage *);
SQUIDCEXTERN int getpagesize(void);
#if !defined(_XPG4_2) && !(defined(__EXTENSIONS__) || \
(!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)))
SQUIDCEXTERN int gethostname(char *, int);
#endif
#endif

/*
 * hack to allow snmp access to the statistics counters
 */
class StatCounters;
        SQUIDCEXTERN StatCounters *snmpStatGet(int);

        /* CygWin & Windows NT Port */
        /* win32.c */
#if _SQUID_WINDOWS_
        SQUIDCEXTERN int WIN32_Subsystem_Init(int *, char ***);
        SQUIDCEXTERN void WIN32_sendSignal(int);
        SQUIDCEXTERN void WIN32_Abort(int);
        SQUIDCEXTERN void WIN32_Exit(void);
        SQUIDCEXTERN void WIN32_SetServiceCommandLine(void);
        SQUIDCEXTERN void WIN32_InstallService(void);
        SQUIDCEXTERN void WIN32_RemoveService(void);
        SQUIDCEXTERN int SquidMain(int, char **);
#endif /* _SQUID_WINDOWS_ */
#if _SQUID_MSWIN_

        SQUIDCEXTERN int WIN32_pipe(int[2]);

            SQUIDCEXTERN int WIN32_getrusage(int, struct rusage *);
    SQUIDCEXTERN void WIN32_ExceptionHandlerInit(void);

    SQUIDCEXTERN int Win32__WSAFDIsSet(int fd, fd_set* set);
    SQUIDCEXTERN DWORD WIN32_IpAddrChangeMonitorInit();

#endif

    extern char *strtokFile(void);

#if USE_AUTH

#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI
    /* upstream proxy authentication */
    SQUIDCEXTERN char *peer_proxy_negotiate_auth(char *principal_name, char *proxy);
#endif

    namespace Auth {
    /* call to ensure the auth component schemes exist. */
    extern void Init(void);
    } // namespace Auth

#endif /* USE_AUTH */

#endif /* SQUID_PROTOS_H */
