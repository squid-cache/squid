/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Misc Functions */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/Subscription.h"
#include "client_side.h"
#include "fatal.h"
#include "fde.h"
#include "fqdncache.h"
#include "fs_io.h"
#include "htcp.h"
#include "http/Stream.h"
#include "ICP.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "ipc/Coordinator.h"
#include "ipc/Kids.h"
#include "ipcache.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "store/Disks.h"
#include "tools.h"
#include "wordlist.h"

#include <cerrno>
#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#if HAVE_WIN32_PSAPI
#include <psapi.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif

#define DEAD_MSG "\
The Squid Cache (version %s) died.\n\
\n\
You've encountered a fatal error in the Squid Cache version %s.\n\
If a core file was created (possibly in the swap directory),\n\
please execute 'gdb squid core' or 'dbx squid core', then type 'where',\n\
and report the trace back to squid-bugs@squid-cache.org.\n\
\n\
Thanks!\n"

static void mail_warranty(void);
static void restoreCapabilities(bool keep);
int DebugSignal = -1;
SBuf service_name(APP_SHORTNAME);

#if _SQUID_LINUX_
/* Workaround for crappy glic header files */
SQUIDCEXTERN int backtrace(void *, int);
SQUIDCEXTERN void backtrace_symbols_fd(void *, int, int);
SQUIDCEXTERN int setresuid(uid_t, uid_t, uid_t);
#else /* _SQUID_LINUX_ */
/* needed on Opensolaris for backtrace_symbols_fd */
#if HAVE_EXECINFO_H
#include <execinfo.h>
#endif /* HAVE_EXECINFO_H */

#endif /* _SQUID_LINUX */

void
releaseServerSockets(void)
{
    // Release the main ports as early as possible

    // clear http_port, https_port, and ftp_port lists
    clientConnectionsClose();

    // clear icp_port's
    icpClosePorts();

    // XXX: Why not the HTCP, SNMP, DNS ports as well?
    // XXX: why does this differ from main closeServerConnections() anyway ?
}

static char *
dead_msg(void)
{
    LOCAL_ARRAY(char, msg, 1024);
    snprintf(msg, 1024, DEAD_MSG, version_string, version_string);
    return msg;
}

static void
mail_warranty(void)
{
    FILE *fp = NULL;
    static char command[256];

    /*
     * NP: umask() takes the mask of bits we DONT want set.
     *
     * We want the current user to have read/write access
     * and since this file will be passed to mailsystem,
     * the group and other must have read access.
     */
    const mode_t prev_umask=umask(S_IXUSR|S_IXGRP|S_IWGRP|S_IWOTH|S_IXOTH);

#if HAVE_MKSTEMP
    char filename[] = "/tmp/squid-XXXXXX";
    int tfd = mkstemp(filename);
    if (tfd < 0 || (fp = fdopen(tfd, "w")) == NULL) {
        umask(prev_umask);
        return;
    }
#else
    char *filename;
    // XXX tempnam is obsolete since POSIX.2008-1
    // tmpfile is not an option, we want the created files to stick around
    if ((filename = tempnam(NULL, APP_SHORTNAME)) == NULL ||
            (fp = fopen(filename, "w")) == NULL) {
        umask(prev_umask);
        return;
    }
#endif
    umask(prev_umask);

    if (Config.EmailFrom)
        fprintf(fp, "From: %s\n", Config.EmailFrom);
    else
        fprintf(fp, "From: %s@%s\n", APP_SHORTNAME, uniqueHostname());

    fprintf(fp, "To: %s\n", Config.adminEmail);
    fprintf(fp, "Subject: %s\n", dead_msg());
    fclose(fp);

    snprintf(command, 256, "%s %s < %s", Config.EmailProgram, Config.adminEmail, filename);
    if (system(command)) {}     /* XXX should avoid system(3) */
    unlink(filename);
#if !HAVE_MKSTEMP
    xfree(filename); // tempnam() requires us to free its allocation
#endif
}

void
dumpMallocStats(void)
{
#if HAVE_MSTATS && HAVE_GNUMALLOC_H

    struct mstats ms = mstats();
    fprintf(debug_log, "\ttotal space in arena:  %6d KB\n",
            (int) (ms.bytes_total >> 10));
    fprintf(debug_log, "\tTotal free:            %6d KB %d%%\n",
            (int) (ms.bytes_free >> 10),
            Math::intPercent(ms.bytes_free, ms.bytes_total));
#endif
}

void
squid_getrusage(struct rusage *r)
{
    memset(r, '\0', sizeof(struct rusage));
#if HAVE_GETRUSAGE && defined(RUSAGE_SELF) && !_SQUID_WINDOWS_
#if _SQUID_SOLARIS_
    /* Solaris 2.5 has getrusage() permission bug -- Arjan de Vet */
    enter_suid();
#endif

    getrusage(RUSAGE_SELF, r);

#if _SQUID_SOLARIS_
    leave_suid();
#endif

#elif _SQUID_WINDOWS_ && HAVE_WIN32_PSAPI
    // Windows has an alternative method if there is no POSIX getrusage defined.
    if (WIN32_OS_version >= _WIN_OS_WINNT) {
        /* On Windows NT and later call PSAPI.DLL for process Memory */
        /* informations -- Guido Serassio                       */
        HANDLE hProcess;
        PROCESS_MEMORY_COUNTERS pmc;
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_READ,
                               FALSE, GetCurrentProcessId());
        {
            /* Microsoft CRT doesn't have getrusage function,  */
            /* so we get process CPU time information from PSAPI.DLL. */
            FILETIME ftCreate, ftExit, ftKernel, ftUser;
            if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                int64_t *ptUser = (int64_t *)&ftUser;
                int64_t tUser64 = *ptUser / 10;
                int64_t *ptKernel = (int64_t *)&ftKernel;
                int64_t tKernel64 = *ptKernel / 10;
                r->ru_utime.tv_sec =(long)(tUser64 / 1000000);
                r->ru_stime.tv_sec =(long)(tKernel64 / 1000000);
                r->ru_utime.tv_usec =(long)(tUser64 % 1000000);
                r->ru_stime.tv_usec =(long)(tKernel64 % 1000000);
            } else {
                CloseHandle( hProcess );
                return;
            }
        }
        if (GetProcessMemoryInfo( hProcess, &pmc, sizeof(pmc))) {
            r->ru_maxrss=(DWORD)(pmc.WorkingSetSize / getpagesize());
            r->ru_majflt=pmc.PageFaultCount;
        } else {
            CloseHandle( hProcess );
            return;
        }

        CloseHandle( hProcess );
    }
#endif
}

double

rusage_cputime(struct rusage *r)
{
    return (double) r->ru_stime.tv_sec +
           (double) r->ru_utime.tv_sec +
           (double) r->ru_stime.tv_usec / 1000000.0 +
           (double) r->ru_utime.tv_usec / 1000000.0;
}

/* Hack for some HP-UX preprocessors */
#ifndef HAVE_GETPAGESIZE
#define HAVE_GETPAGESIZE 0
#endif

int

rusage_maxrss(struct rusage *r)
{
#if _SQUID_SGI_ && _ABIAPI
    return r->ru_pad[0];
#elif _SQUID_SGI_|| _SQUID_OSF_ || _SQUID_AIX_ || defined(BSD4_4)

    return r->ru_maxrss;
#elif defined(HAVE_GETPAGESIZE) && HAVE_GETPAGESIZE != 0

    return (r->ru_maxrss * getpagesize()) >> 10;
#elif defined(PAGESIZE)

    return (r->ru_maxrss * PAGESIZE) >> 10;
#else

    return r->ru_maxrss;
#endif
}

int

rusage_pagefaults(struct rusage *r)
{
#if _SQUID_SGI_ && _ABIAPI
    return r->ru_pad[5];
#else

    return r->ru_majflt;
#endif
}

void
PrintRusage(void)
{

    struct rusage rusage;
    squid_getrusage(&rusage);
    fprintf(debug_log, "CPU Usage: %.3f seconds = %.3f user + %.3f sys\n",
            rusage_cputime(&rusage),
            rusage.ru_utime.tv_sec + ((double) rusage.ru_utime.tv_usec / 1000000.0),
            rusage.ru_stime.tv_sec + ((double) rusage.ru_stime.tv_usec / 1000000.0));
    fprintf(debug_log, "Maximum Resident Size: %d KB\n",
            rusage_maxrss(&rusage));
    fprintf(debug_log, "Page faults with physical i/o: %d\n",
            rusage_pagefaults(&rusage));
}

void
death(int sig)
{
    if (sig == SIGSEGV)
        fprintf(debug_log, "FATAL: Received Segment Violation...dying.\n");
    else if (sig == SIGBUS)
        fprintf(debug_log, "FATAL: Received Bus Error...dying.\n");
    else
        fprintf(debug_log, "FATAL: Received signal %d...dying.\n", sig);

#if PRINT_STACK_TRACE
#if _SQUID_HPUX_
    {
        extern void U_STACK_TRACE(void);    /* link with -lcl */
        fflush(debug_log);
        dup2(fileno(debug_log), 2);
        U_STACK_TRACE();
    }

#endif /* _SQUID_HPUX_ */
#if _SQUID_SOLARIS_ && HAVE_LIBOPCOM_STACK
    {   /* get ftp://opcom.sun.ca/pub/tars/opcom_stack.tar.gz and */
        extern void opcom_stack_trace(void);    /* link with -lopcom_stack */
        fflush(debug_log);
        dup2(fileno(debug_log), fileno(stdout));
        opcom_stack_trace();
        fflush(stdout);
    }

#endif /* _SQUID_SOLARIS_and HAVE_LIBOPCOM_STACK */
#if HAVE_BACKTRACE_SYMBOLS_FD
    {
        static void *(callarray[8192]);
        int n;
        n = backtrace(callarray, 8192);
        backtrace_symbols_fd(callarray, n, fileno(debug_log));
    }

#endif
#endif /* PRINT_STACK_TRACE */

#if SA_RESETHAND == 0 && !_SQUID_WINDOWS_
    signal(SIGSEGV, SIG_DFL);

    signal(SIGBUS, SIG_DFL);

    signal(sig, SIG_DFL);

#endif

    releaseServerSockets();

    storeDirWriteCleanLogs(0);

    if (!shutting_down) {
        PrintRusage();

        dumpMallocStats();
    }

    if (squid_curtime - SQUID_RELEASE_TIME < 864000) {
        /* skip if more than 10 days old */

        if (Config.adminEmail)
            mail_warranty();

        puts(dead_msg());
    }

    abort();
}

void
BroadcastSignalIfAny(int& sig)
{
    if (sig > 0) {
        if (IamMasterProcess()) {
            for (int i = TheKids.count() - 1; i >= 0; --i) {
                Kid& kid = TheKids.get(i);
                kill(kid.getPid(), sig);
            }
        }
        sig = -1;
    }
}

void
sigusr2_handle(int sig)
{
    static int state = 0;
    /* no debugs() here; bad things happen if the signal is delivered during _db_print() */

    DebugSignal = sig;

    if (state == 0) {
        Debug::parseOptions("ALL,7");
        state = 1;
    } else {
        Debug::parseOptions(Debug::debugOptions);
        state = 0;
    }

#if !HAVE_SIGACTION
    /* reinstall */
    if (signal(sig, sigusr2_handle) == SIG_ERR) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "signal: sig=" << sig << " func=sigusr2_handle: " << xstrerr(xerrno));
    }
#endif
}

void
debug_trap(const char *message)
{
    if (!opt_catch_signals)
        fatal_dump(message);

    _db_print("WARNING: %s\n", message);
}

const char *
getMyHostname(void)
{
    LOCAL_ARRAY(char, host, SQUIDHOSTNAMELEN + 1);
    static int present = 0;
    struct addrinfo *AI = NULL;
    Ip::Address sa;

    if (Config.visibleHostname != NULL)
        return Config.visibleHostname;

    if (present)
        return host;

    host[0] = '\0';

    if (HttpPortList != NULL && sa.isAnyAddr())
        sa = HttpPortList->s;

    /*
     * If the first http_port address has a specific address, try a
     * reverse DNS lookup on it.
     */
    if ( !sa.isAnyAddr() ) {

        sa.getAddrInfo(AI);
        /* we are looking for a name. */
        if (getnameinfo(AI->ai_addr, AI->ai_addrlen, host, SQUIDHOSTNAMELEN, NULL, 0, NI_NAMEREQD ) == 0) {
            /* DNS lookup successful */
            /* use the official name from DNS lookup */
            debugs(50, 4, "getMyHostname: resolved " << sa << " to '" << host << "'");

            present = 1;

            Ip::Address::FreeAddr(AI);

            if (strchr(host, '.'))
                return host;
        }

        Ip::Address::FreeAddr(AI);
        debugs(50, 2, "WARNING: failed to resolve " << sa << " to a fully qualified hostname");
    }

    // still no host. fallback to gethostname()
    if (gethostname(host, SQUIDHOSTNAMELEN) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "WARNING: gethostname failed: " << xstrerr(xerrno));
    } else {
        /* Verify that the hostname given resolves properly */
        struct addrinfo hints;
        memset(&hints, 0, sizeof(addrinfo));
        hints.ai_flags = AI_CANONNAME;

        if (getaddrinfo(host, NULL, NULL, &AI) == 0) {
            /* DNS lookup successful */
            /* use the official name from DNS lookup */
            debugs(50, 6, "getMyHostname: '" << host << "' has DNS resolution.");
            present = 1;

            /* AYJ: do we want to flag AI_ALL and cache the result anywhere. ie as our local host IPs? */
            if (AI)
                freeaddrinfo(AI);

            return host;
        }
        int xerrno = errno;

        if (AI)
            freeaddrinfo(AI);
        debugs(50, DBG_IMPORTANT, "WARNING: '" << host << "' rDNS test failed: " << xstrerr(xerrno));
    }

    /* throw a configuration error when the Host/IP given has bad DNS/rDNS. */
    debugs(50, DBG_CRITICAL, "WARNING: Could not determine this machines public hostname. " <<
           "Please configure one or set 'visible_hostname'.");

    return ("localhost");
}

const char *
uniqueHostname(void)
{
    debugs(21, 3, HERE << " Config: '" << Config.uniqueHostname << "'");
    return Config.uniqueHostname ? Config.uniqueHostname : getMyHostname();
}

/** leave a priviliged section. (Give up any privilegies)
 * Routines that need privilegies can rap themselves in enter_suid()
 * and leave_suid()
 * To give upp all posibilites to gain privilegies use no_suid()
 */
void
leave_suid(void)
{
    debugs(21, 3, "leave_suid: PID " << getpid() << " called");

    if (Config.effectiveGroup) {
#if HAVE_SETGROUPS
        setgroups(1, &Config2.effectiveGroupID);
#endif

        if (setgid(Config2.effectiveGroupID) < 0) {
            int xerrno = errno;
            debugs(50, DBG_CRITICAL, "ALERT: setgid: " << xstrerr(xerrno));
        }
    }

    if (geteuid() != 0)
        return;

    /* Started as a root, check suid option */
    if (Config.effectiveUser == NULL)
        return;

    debugs(21, 3, "leave_suid: PID " << getpid() << " giving up root, becoming '" << Config.effectiveUser << "'");

    if (!Config.effectiveGroup) {

        if (setgid(Config2.effectiveGroupID) < 0) {
            int xerrno = errno;
            debugs(50, DBG_CRITICAL, "ALERT: setgid: " << xstrerr(xerrno));
        }

        if (initgroups(Config.effectiveUser, Config2.effectiveGroupID) < 0) {
            debugs(50, DBG_CRITICAL, "ALERT: initgroups: unable to set groups for User " <<
                   Config.effectiveUser << " and Group " <<
                   (unsigned) Config2.effectiveGroupID << "");
        }
    }

#if HAVE_SETRESUID
    if (setresuid(Config2.effectiveUserID, Config2.effectiveUserID, 0) < 0) {
        const auto xerrno = errno;
        fatalf("FATAL: setresuid: %s", xstrerr(xerrno));
    }

#elif HAVE_SETEUID
    if (seteuid(Config2.effectiveUserID) < 0) {
        const auto xerrno = errno;
        fatalf("FATAL: seteuid: %s", xstrerr(xerrno));
    }

#else
    if (setuid(Config2.effectiveUserID) < 0) {
        const auto xerrno = errno;
        fatalf("FATAL: setuid: %s", xstrerr(xerrno));
    }

#endif

    restoreCapabilities(true);

#if HAVE_PRCTL && defined(PR_SET_DUMPABLE)
    /* Set Linux DUMPABLE flag */
    if (Config.coredump_dir && prctl(PR_SET_DUMPABLE, 1) != 0) {
        int xerrno = errno;
        debugs(50, 2, "ALERT: prctl: " << xstrerr(xerrno));
    }
#endif
}

/* Enter a privilegied section */
void
enter_suid(void)
{
    debugs(21, 3, "enter_suid: PID " << getpid() << " taking root privileges");
#if HAVE_SETRESUID
    if (setresuid((uid_t)-1, 0, (uid_t)-1) < 0) {
        const auto xerrno = errno;
        debugs (21, 3, "enter_suid: setresuid failed: " << xstrerr(xerrno));
    }
#else

    setuid(0);
#endif
#if HAVE_PRCTL && defined(PR_SET_DUMPABLE)
    /* Set Linux DUMPABLE flag */

    if (Config.coredump_dir && prctl(PR_SET_DUMPABLE, 1) != 0) {
        int xerrno = errno;
        debugs(50, 2, "ALERT: prctl: " << xstrerr(xerrno));
    }
#endif
}

/* Give up the posibility to gain privilegies.
 * this should be used before starting a sub process
 */
void
no_suid(void)
{
    uid_t uid;
    leave_suid();
    uid = geteuid();
    debugs(21, 3, "no_suid: PID " << getpid() << " giving up root priveleges forever");

    if (setuid(0) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "WARNING: no_suid: setuid(0): " << xstrerr(xerrno));
    }

    if (setuid(uid) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "ERROR: no_suid: setuid(" << uid << "): " << xstrerr(xerrno));
    }

    restoreCapabilities(false);

#if HAVE_PRCTL && defined(PR_SET_DUMPABLE)
    /* Set Linux DUMPABLE flag */
    if (Config.coredump_dir && prctl(PR_SET_DUMPABLE, 1) != 0) {
        int xerrno = errno;
        debugs(50, 2, "ALERT: prctl: " << xstrerr(xerrno));
    }
#endif
}

bool
IamMasterProcess()
{
    return KidIdentifier == 0;
}

bool
IamWorkerProcess()
{
    // when there is only one process, it has to be the worker
    if (opt_no_daemon || Config.workers == 0)
        return true;

    return TheProcessKind == pkWorker;
}

bool
IamDiskProcess()
{
    return TheProcessKind == pkDisker;
}

bool
InDaemonMode()
{
    return !opt_no_daemon && Config.workers > 0;
}

bool
UsingSmp()
{
    return InDaemonMode() && NumberOfKids() > 1;
}

bool
IamCoordinatorProcess()
{
    return TheProcessKind == pkCoordinator;
}

bool
IamPrimaryProcess()
{
    // when there is only one process, it has to be primary
    if (opt_no_daemon || Config.workers == 0)
        return true;

    // when there is a master and worker process, the master delegates
    // primary functions to its only kid
    if (NumberOfKids() == 1)
        return IamWorkerProcess();

    // in SMP mode, multiple kids delegate primary functions to the coordinator
    return IamCoordinatorProcess();
}

int
NumberOfKids()
{
    // no kids in no-daemon mode
    if (!InDaemonMode())
        return 0;

    // XXX: detect and abort when called before workers/cache_dirs are parsed

    const int rockDirs = Config.cacheSwap.n_strands;

    const bool needCoord = Config.workers > 1 || rockDirs > 0;
    return (needCoord ? 1 : 0) + Config.workers + rockDirs;
}

SBuf
ProcessRoles()
{
    SBuf roles;
    if (IamMasterProcess())
        roles.append(" master");
    if (IamCoordinatorProcess())
        roles.append(" coordinator");
    if (IamWorkerProcess())
        roles.append(" worker");
    if (IamDiskProcess())
        roles.append(" disker");
    return roles;
}

void
writePidFile(void)
{
    int fd;
    const char *f = NULL;
    mode_t old_umask;
    char buf[32];

    debugs(50, DBG_IMPORTANT, "creating PID file: " << Config.pidFilename);

    if ((f = Config.pidFilename) == NULL)
        return;

    if (!strcmp(Config.pidFilename, "none"))
        return;

    enter_suid();

    old_umask = umask(022);

    fd = open(f, O_WRONLY | O_CREAT | O_TRUNC | O_TEXT, 0644);
    int xerrno = errno;

    umask(old_umask);

    leave_suid();

    if (fd < 0) {
        debugs(50, DBG_CRITICAL, "" << f << ": " << xstrerr(xerrno));
        debug_trap("Could not open PID file for write");
        return;
    }

    snprintf(buf, 32, "%d\n", (int) getpid());
    const size_t ws = write(fd, buf, strlen(buf));
    assert(ws == strlen(buf));
    close(fd);
}

void
removePidFile()
{
    if (Config.pidFilename && strcmp(Config.pidFilename, "none") != 0) {
        debugs(50, DBG_IMPORTANT, "removing PID file: " << Config.pidFilename);
        enter_suid();
        safeunlink(Config.pidFilename, 0);
        leave_suid();
    }
}

pid_t
readPidFile(void)
{
    FILE *pid_fp = NULL;
    const char *f = Config.pidFilename;
    char *chroot_f = NULL;
    pid_t pid = -1;
    int i;

    if (f == NULL || !strcmp(Config.pidFilename, "none")) {
        fprintf(stderr, APP_SHORTNAME ": ERROR: No PID file name defined\n");
        exit(1);
    }

    if (Config.chroot_dir && geteuid() == 0) {
        int len = strlen(Config.chroot_dir) + 1 + strlen(f) + 1;
        chroot_f = (char *)xmalloc(strlen(Config.chroot_dir) + 1 + strlen(f) + 1);
        snprintf(chroot_f, len, "%s/%s", Config.chroot_dir, f);
        f = chroot_f;
    }

    if ((pid_fp = fopen(f, "r"))) {
        pid = 0;

        if (fscanf(pid_fp, "%d", &i) == 1)
            pid = (pid_t) i;

        fclose(pid_fp);
    } else {
        int xerrno = errno;
        if (xerrno != ENOENT) {
            fprintf(stderr, APP_SHORTNAME ": ERROR: Could not open PID file for read\n");
            fprintf(stderr, "\t%s: %s\n", f, xstrerr(xerrno));
            exit(1);
        }
    }

    safe_free(chroot_f);
    return pid;
}

/* A little piece of glue for odd systems */
#ifndef RLIMIT_NOFILE
#ifdef RLIMIT_OFILE
#define RLIMIT_NOFILE RLIMIT_OFILE
#endif
#endif

/** Figure out the number of supported filedescriptors */
void
setMaxFD(void)
{
#if HAVE_SETRLIMIT && defined(RLIMIT_NOFILE)

    /* On Linux with 64-bit file support the sys/resource.h header
     * uses #define to change the function definition to require rlimit64
     */
#if defined(getrlimit)
    struct rlimit64 rl; // Assume its a 64-bit redefine anyways.
#else
    struct rlimit rl;
#endif

    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "getrlimit: RLIMIT_NOFILE: " << xstrerr(xerrno));
    } else if (Config.max_filedescriptors > 0) {
#if USE_SELECT || USE_SELECT_WIN32
        /* select() breaks if this gets set too big */
        if (Config.max_filedescriptors > FD_SETSIZE) {
            rl.rlim_cur = FD_SETSIZE;
            debugs(50, DBG_CRITICAL, "WARNING: 'max_filedescriptors " << Config.max_filedescriptors << "' does not work with select()");
        } else
#endif
            rl.rlim_cur = Config.max_filedescriptors;
        if (rl.rlim_cur > rl.rlim_max)
            rl.rlim_max = rl.rlim_cur;
        if (setrlimit(RLIMIT_NOFILE, &rl)) {
            int xerrno = errno;
            debugs(50, DBG_CRITICAL, "ERROR: setrlimit: RLIMIT_NOFILE: " << xstrerr(xerrno));
            getrlimit(RLIMIT_NOFILE, &rl);
            rl.rlim_cur = rl.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &rl)) {
                xerrno = errno;
                debugs(50, DBG_CRITICAL, "ERROR: setrlimit: RLIMIT_NOFILE: " << xstrerr(xerrno));
            }
        }
    }
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "ERROR: getrlimit: RLIMIT_NOFILE: " << xstrerr(xerrno));
    } else {
        Squid_MaxFD = rl.rlim_cur;
    }

#endif /* HAVE_SETRLIMIT */
}

void
setSystemLimits(void)
{
#if HAVE_SETRLIMIT && defined(RLIMIT_NOFILE) && !_SQUID_CYGWIN_
    /* limit system filedescriptors to our own limit */

    /* On Linux with 64-bit file support the sys/resource.h header
     * uses #define to change the function definition to require rlimit64
     */
#if defined(getrlimit)
    struct rlimit64 rl; // Assume its a 64-bit redefine anyways.
#else
    struct rlimit rl;
#endif

    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "getrlimit: RLIMIT_NOFILE: " << xstrerr(xerrno));
    } else {
        rl.rlim_cur = Squid_MaxFD;
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
            int xerrno = errno;
            snprintf(tmp_error_buf, ERROR_BUF_SZ, "setrlimit: RLIMIT_NOFILE: %s", xstrerr(xerrno));
            fatal_dump(tmp_error_buf);
        }
    }
#endif /* HAVE_SETRLIMIT */

#if HAVE_SETRLIMIT && defined(RLIMIT_DATA) && !_SQUID_CYGWIN_
    if (getrlimit(RLIMIT_DATA, &rl) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "getrlimit: RLIMIT_DATA: " << xstrerr(xerrno));
    } else if (rl.rlim_max > rl.rlim_cur) {
        rl.rlim_cur = rl.rlim_max;  /* set it to the max */

        if (setrlimit(RLIMIT_DATA, &rl) < 0) {
            int xerrno = errno;
            snprintf(tmp_error_buf, ERROR_BUF_SZ, "setrlimit: RLIMIT_DATA: %s", xstrerr(xerrno));
            fatal_dump(tmp_error_buf);
        }
    }
#endif /* RLIMIT_DATA */
    if (Config.max_filedescriptors > Squid_MaxFD) {
        debugs(50, DBG_IMPORTANT, "NOTICE: Could not increase the number of filedescriptors");
    }

#if HAVE_SETRLIMIT && defined(RLIMIT_VMEM) && !_SQUID_CYGWIN_
    if (getrlimit(RLIMIT_VMEM, &rl) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "getrlimit: RLIMIT_VMEM: " << xstrerr(xerrno));
    } else if (rl.rlim_max > rl.rlim_cur) {
        rl.rlim_cur = rl.rlim_max;  /* set it to the max */

        if (setrlimit(RLIMIT_VMEM, &rl) < 0) {
            int xerrno = errno;
            snprintf(tmp_error_buf, ERROR_BUF_SZ, "setrlimit: RLIMIT_VMEM: %s", xstrerr(xerrno));
            fatal_dump(tmp_error_buf);
        }
    }
#endif /* RLIMIT_VMEM */
}

void
squid_signal(int sig, SIGHDLR * func, int flags)
{
#if HAVE_SIGACTION

    struct sigaction sa;
    sa.sa_handler = func;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);

    if (sigaction(sig, &sa, NULL) < 0) {
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "sigaction: sig=" << sig << " func=" << func << ": " << xstrerr(xerrno));
    }
#else
#if _SQUID_WINDOWS_
    /*
    On Windows, only SIGINT, SIGILL, SIGFPE, SIGTERM, SIGBREAK, SIGABRT and SIGSEGV signals
    are supported, so we must care of don't call signal() for other value.
    The SIGILL, SIGSEGV, and SIGTERM signals are not generated under Windows. They are defined
    for ANSI compatibility, so both SIGSEGV and SIGBUS are emulated with an Exception Handler.
    */
    switch (sig) {

    case SIGINT:

    case SIGILL:

    case SIGFPE:

    case SIGTERM:

    case SIGBREAK:

    case SIGABRT:
        break;

    case SIGSEGV:
        WIN32_ExceptionHandlerInit();
        break;

    case SIGBUS:
        WIN32_ExceptionHandlerInit();
        return;
        break;  /* Nor reached */

    default:
        return;
        break;  /* Nor reached */
    }

#endif

    signal(sig, func);

#endif
}

void
logsFlush(void)
{
    if (debug_log)
        fflush(debug_log);
}

void
debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm)
{
    assert(label && obj && pm);
    MemBuf mb;
    mb.init();
    (*pm) (obj, &mb);
    debugs(section, level, "" << label << "" << mb.buf << "");
    mb.clean();
}

void
parseEtcHosts(void)
{
    char buf[1024];
    char buf2[512];
    char *nt = buf;
    char *lt = buf;

    if (!Config.etcHostsPath)
        return;

    if (0 == strcmp(Config.etcHostsPath, "none"))
        return;

    FILE *fp = fopen(Config.etcHostsPath, "r");

    if (!fp) {
        int xerrno = errno;
        debugs(1, DBG_IMPORTANT, "parseEtcHosts: '" << Config.etcHostsPath << "' : " << xstrerr(xerrno));
        return;
    }

#if _SQUID_WINDOWS_
    setmode(fileno(fp), O_TEXT);
#endif

    while (fgets(buf, 1024, fp)) {  /* for each line */

        if (buf[0] == '#')  /* MS-windows likes to add comments */
            continue;

        strtok(buf, "#");   /* chop everything following a comment marker */

        lt = buf;

        char *addr = buf;

        debugs(1, 5, "etc_hosts: line is '" << buf << "'");

        nt = strpbrk(lt, w_space);

        if (nt == NULL)     /* empty line */
            continue;

        *nt = '\0';     /* null-terminate the address */

        debugs(1, 5, "etc_hosts: address is '" << addr << "'");

        lt = nt + 1;

        SBufList hosts;

        while ((nt = strpbrk(lt, w_space))) {
            char *host = NULL;

            if (nt == lt) { /* multiple spaces */
                debugs(1, 5, "etc_hosts: multiple spaces, skipping");
                lt = nt + 1;
                continue;
            }

            *nt = '\0';
            debugs(1, 5, "etc_hosts: got hostname '" << lt << "'");

            /* For IPV6 addresses also check for a colon */
            if (Config.appendDomain && !strchr(lt, '.') && !strchr(lt, ':')) {
                /* I know it's ugly, but it's only at reconfig */
                strncpy(buf2, lt, sizeof(buf2)-1);
                strncat(buf2, Config.appendDomain, sizeof(buf2) - strlen(lt) - 1);
                buf2[sizeof(buf2)-1] = '\0';
                host = buf2;
            } else {
                host = lt;
            }

            if (ipcacheAddEntryFromHosts(host, addr) != 0) {
                /* invalid address, continuing is useless */
                hosts.clear();
                break;
            }
            hosts.emplace_back(SBuf(host));

            lt = nt + 1;
        }

        if (!hosts.empty())
            fqdncacheAddEntryFromHosts(addr, hosts);
    }

    fclose (fp);
}

int
getMyPort(void)
{
    AnyP::PortCfgPointer p;
    if ((p = HttpPortList) != NULL) {
        // skip any special interception ports
        while (p != NULL && p->flags.isIntercepted())
            p = p->next;
        if (p != NULL)
            return p->s.port();
    }

    if ((p = FtpPortList) != NULL) {
        // skip any special interception ports
        while (p != NULL && p->flags.isIntercepted())
            p = p->next;
        if (p != NULL)
            return p->s.port();
    }

    debugs(21, DBG_CRITICAL, "ERROR: No forward-proxy ports configured.");
    return 0; // Invalid port. This will result in invalid URLs on bad configurations.
}

/*
 * Set the umask to at least the given mask. This is in addition
 * to the umask set at startup
 */
void
setUmask(mode_t mask)
{
    // No way to get the current umask value without setting it.
    static const mode_t orig_umask = umask(mask); // once, to get
    umask(mask | orig_umask); // always, to set
}

/*
 * Inverse of strwordtok. Quotes a word if needed
 */
void
strwordquote(MemBuf * mb, const char *str)
{
    int quoted = 0;

    if (strchr(str, ' ')) {
        quoted = 1;
        mb->append("\"", 1);
    }

    while (*str) {
        int l = strcspn(str, "\"\\\n\r");
        mb->append(str, l);
        str += l;

        switch (*str) {

        case '\n':
            mb->append("\\n", 2);
            ++str;
            break;

        case '\r':
            mb->append("\\r", 2);
            ++str;
            break;

        case '\0':
            break;

        default:
            mb->append("\\", 1);
            mb->append(str, 1);
            ++str;
            break;
        }
    }

    if (quoted)
        mb->append("\"", 1);
}

void
keepCapabilities(void)
{
#if USE_LIBCAP && HAVE_PRCTL && defined(PR_SET_KEEPCAPS)

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
        Ip::Interceptor.StopTransparency("capability setting has failed.");
    }
#endif
}

static void
restoreCapabilities(bool keep)
{
    /* NP: keep these two if-endif separate. Non-Linux work perfectly well without Linux syscap support. */
#if USE_LIBCAP
    cap_t caps;
    if (keep)
        caps = cap_get_proc();
    else
        caps = cap_init();
    if (!caps) {
        Ip::Interceptor.StopTransparency("Can't get current capabilities");
    } else {
        int ncaps = 0;
        int rc = 0;
        cap_value_t cap_list[10];
        cap_list[ncaps] = CAP_NET_BIND_SERVICE;
        ++ncaps;
        if (Ip::Interceptor.TransparentActive() ||
                Ip::Qos::TheConfig.isHitNfmarkActive() ||
                Ip::Qos::TheConfig.isAclNfmarkActive() ||
                Ip::Qos::TheConfig.isAclTosActive()) {
            cap_list[ncaps] = CAP_NET_ADMIN;
            ++ncaps;
        }

        cap_clear_flag(caps, CAP_EFFECTIVE);
        rc |= cap_set_flag(caps, CAP_EFFECTIVE, ncaps, cap_list, CAP_SET);
        rc |= cap_set_flag(caps, CAP_PERMITTED, ncaps, cap_list, CAP_SET);

        if (rc || cap_set_proc(caps) != 0) {
            Ip::Interceptor.StopTransparency("Error enabling needed capabilities.");
        }
        cap_free(caps);
    }
#elif _SQUID_LINUX_
    Ip::Interceptor.StopTransparency("Missing needed capability support.");
#endif /* HAVE_SYS_CAPABILITY_H */
}

pid_t
WaitForOnePid(pid_t pid, PidStatus &status, int flags)
{
#if _SQUID_NEXT_
    if (pid < 0)
        return wait3(&status, flags, NULL);
    return wait4(pid, &status, flags, NULL);
#elif _SQUID_WINDOWS_
    return 0; // function not used on Windows
#else
    return waitpid(pid, &status, flags);
#endif
}

