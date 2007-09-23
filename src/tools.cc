
/*
 * $Id: tools.cc,v 1.279 2007/09/23 09:18:10 serassio Exp $
 *
 * DEBUG: section 21    Misc Functions
 * AUTHOR: Harvest Derived
 *
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

#include "squid.h"
#include "SwapDir.h"
#include "fde.h"
#include "MemBuf.h"
#include "wordlist.h"
#include "SquidTime.h"

#ifdef _SQUID_LINUX_
#if HAVE_SYS_CAPABILITY_H
#undef _POSIX_SOURCE
/* Ugly glue to get around linux header madness colliding with glibc */
#define _LINUX_TYPES_H
#define _LINUX_FS_H
typedef uint32_t __u32;
#include <sys/capability.h>
#endif
#endif

#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
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

static void fatal_common(const char *);
static void fatalvf(const char *fmt, va_list args);
static void mail_warranty(void);
#if MEM_GEN_TRACE
extern void log_trace_done();
extern void log_trace_init(char *);
#endif
static void restoreCapabilities(int keep);

#ifdef _SQUID_LINUX_
/* Workaround for crappy glic header files */
SQUIDCEXTERN int backtrace(void *, int);
SQUIDCEXTERN void backtrace_symbols_fd(void *, int, int);
SQUIDCEXTERN int setresuid(uid_t, uid_t, uid_t);
#endif /* _SQUID_LINUX */

SQUIDCEXTERN void (*failure_notify) (const char *);

MemAllocator *dlink_node_pool = NULL;

void
releaseServerSockets(void)
{
    int i;
    /* Release the main ports as early as possible */

    for (i = 0; i < NHttpSockets; i++) {
        if (HttpSockets[i] >= 0)
            close(HttpSockets[i]);
    }

    if (theInIcpConnection >= 0)
        close(theInIcpConnection);

    if (theOutIcpConnection >= 0 && theOutIcpConnection != theInIcpConnection)
        close(theOutIcpConnection);
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
#if HAVE_MKSTEMP

    char filename[] = "/tmp/squid-XXXXXX";
    int tfd = mkstemp(filename);

    if (tfd < 0)
        return;

    if ((fp = fdopen(tfd, "w")) == NULL)
        return;

#else

    char *filename;

    if ((filename = tempnam(NULL, appname)) == NULL)
        return;

    if ((fp = fopen(filename, "w")) == NULL)
        return;

#endif

    if (Config.EmailFrom)
        fprintf(fp, "From: %s\n", Config.EmailFrom);
    else
        fprintf(fp, "From: %s@%s\n", appname, uniqueHostname());

    fprintf(fp, "To: %s\n", Config.adminEmail);

    fprintf(fp, "Subject: %s\n", dead_msg());

    fclose(fp);

    snprintf(command, 256, "%s %s < %s", Config.EmailProgram, Config.adminEmail, filename);

    system(command);		/* XXX should avoid system(3) */

    unlink(filename);
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
            percent(ms.bytes_free, ms.bytes_total));
#elif HAVE_MALLINFO && HAVE_STRUCT_MALLINFO

    struct mallinfo mp;
    int t;

    if (!do_mallinfo)
        return;

    mp = mallinfo();

    fprintf(debug_log, "Memory usage for %s via mallinfo():\n", appname);

    fprintf(debug_log, "\ttotal space in arena:  %6ld KB\n",
            (long)mp.arena >> 10);

    fprintf(debug_log, "\tOrdinary blocks:       %6ld KB %6ld blks\n",
            (long)mp.uordblks >> 10, (long)mp.ordblks);

    fprintf(debug_log, "\tSmall blocks:          %6ld KB %6ld blks\n",
            (long)mp.usmblks >> 10, (long)mp.smblks);

    fprintf(debug_log, "\tHolding blocks:        %6ld KB %6ld blks\n",
            (long)mp.hblkhd >> 10, (long)mp.hblks);

    fprintf(debug_log, "\tFree Small blocks:     %6ld KB\n",
            (long)mp.fsmblks >> 10);

    fprintf(debug_log, "\tFree Ordinary blocks:  %6ld KB\n",
            (long)mp.fordblks >> 10);

    t = mp.uordblks + mp.usmblks + mp.hblkhd;

    fprintf(debug_log, "\tTotal in use:          %6d KB %d%%\n",
            t >> 10, percent(t, mp.arena));

    t = mp.fsmblks + mp.fordblks;

    fprintf(debug_log, "\tTotal free:            %6d KB %d%%\n",
            t >> 10, percent(t, mp.arena));

#if HAVE_STRUCT_MALLINFO_MXFAST

    fprintf(debug_log, "\tmax size of small blocks:\t%d\n",
            mp.mxfast);

    fprintf(debug_log, "\tnumber of small blocks in a holding block:\t%d\n",
            mp.nlblks);

    fprintf(debug_log, "\tsmall block rounding factor:\t%d\n",
            mp.grain);

    fprintf(debug_log, "\tspace (including overhead) allocated in ord. blks:\t%d\n",
            mp.uordbytes);

    fprintf(debug_log, "\tnumber of ordinary blocks allocated:\t%d\n",
            mp.allocated);

    fprintf(debug_log, "\tbytes used in maintaining the free tree:\t%d\n",
            mp.treeoverhead);

#endif /* HAVE_STRUCT_MALLINFO_MXFAST */
#endif /* HAVE_MALLINFO */
}

void

squid_getrusage(struct rusage *r)
{

    memset(r, '\0', sizeof(struct rusage));
#if HAVE_GETRUSAGE && defined(RUSAGE_SELF)
#ifdef _SQUID_SOLARIS_
    /* Solaris 2.5 has getrusage() permission bug -- Arjan de Vet */
    enter_suid();
#endif

    getrusage(RUSAGE_SELF, r);
#ifdef _SQUID_SOLARIS_

    leave_suid();
#endif
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
#if defined(_SQUID_SGI_) && _ABIAPI
    return r->ru_pad[0];
#elif defined(_SQUID_SGI_)

    return r->ru_maxrss;
#elif defined(_SQUID_OSF_)

    return r->ru_maxrss;
#elif defined(_SQUID_AIX_)

    return r->ru_maxrss;
#elif defined(BSD4_4)

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
#if defined(_SQUID_SGI_) && _ABIAPI
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

#ifdef PRINT_STACK_TRACE
#ifdef _SQUID_HPUX_
    {
        extern void U_STACK_TRACE(void);	/* link with -lcl */
        fflush(debug_log);
        dup2(fileno(debug_log), 2);
        U_STACK_TRACE();
    }

#endif /* _SQUID_HPUX_ */
#ifdef _SQUID_SOLARIS_
    {				/* get ftp://opcom.sun.ca/pub/tars/opcom_stack.tar.gz and */
        extern void opcom_stack_trace(void);	/* link with -lopcom_stack */
        fflush(debug_log);
        dup2(fileno(debug_log), fileno(stdout));
        opcom_stack_trace();
        fflush(stdout);
    }

#endif /* _SQUID_SOLARIS_ */
#if HAVE_BACKTRACE_SYMBOLS_FD
    {
        static void *(callarray[8192]);
        int n;
        n = backtrace(callarray, 8192);
        backtrace_symbols_fd(callarray, n, fileno(debug_log));
    }

#endif
#endif /* PRINT_STACK_TRACE */

#if SA_RESETHAND == 0 && !defined(_SQUID_MSWIN_)
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

    if (shutting_down)
        exit(1);

    abort();
}


void
sigusr2_handle(int sig)
{
    static int state = 0;
    /* no debug() here; bad things happen if the signal is delivered during _db_print() */

    if (state == 0) {
#ifndef MEM_GEN_TRACE
        Debug::parseOptions("ALL,7");
#else

        log_trace_done();
#endif

        state = 1;
    } else {
#ifndef MEM_GEN_TRACE
        Debug::parseOptions(Config.debugOptions);
#else

        log_trace_init("/tmp/squid.alloc");
#endif

        state = 0;
    }

#if !HAVE_SIGACTION
    if (signal(sig, sigusr2_handle) == SIG_ERR)	/* reinstall */
        debugs(50, 0, "signal: sig=" << sig << " func=sigusr2_handle: " << xstrerror());

#endif
}

static void
fatal_common(const char *message)
{
#if HAVE_SYSLOG
    syslog(LOG_ALERT, "%s", message);
#endif

    fprintf(debug_log, "FATAL: %s\n", message);

    if (opt_debug_stderr > 0 && debug_log != stderr)
        fprintf(stderr, "FATAL: %s\n", message);

    fprintf(debug_log, "Squid Cache (Version %s): Terminated abnormally.\n",
            version_string);

    fflush(debug_log);

    PrintRusage();

    dumpMallocStats();
}

/* fatal */
void
fatal(const char *message)
{
    releaseServerSockets();
    /* check for store_dirs_rebuilding because fatal() is often
     * used in early initialization phases, long before we ever
     * get to the store log. */

    /* XXX: this should be turned into a callback-on-fatal, or
     * a mandatory-shutdown-event or something like that.
     * - RBC 20060819
     */

    /*
     * DPW 2007-07-06
     * Call leave_suid() here to make sure that swap.state files
     * are written as the effective user, rather than root.  Squid
     * may take on root privs during reconfigure.  If squid.conf
     * contains a "Bungled" line, fatal() will be called when the
     * process still has root privs.
     */
    leave_suid();

    if (0 == StoreController::store_dirs_rebuilding)
        storeDirWriteCleanLogs(0);

    fatal_common(message);

    exit(1);
}

/* printf-style interface for fatal */
#if STDC_HEADERS
void
fatalf(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
#else
void
fatalf(va_alist)
va_dcl
{
    va_list args;
    const char *fmt = NULL;
    va_start(args);
    fmt = va_arg(args, char *);
#endif

    fatalvf(fmt, args);
    va_end(args);
}


/* used by fatalf */
static void
fatalvf(const char *fmt, va_list args) {
    static char fatal_str[BUFSIZ];
    vsnprintf(fatal_str, sizeof(fatal_str), fmt, args);
    fatal(fatal_str);
}

/* fatal with dumping core */
void
fatal_dump(const char *message) {
    failure_notify = NULL;
    releaseServerSockets();

    if (message)
        fatal_common(message);

    /*
     * Call leave_suid() here to make sure that swap.state files
     * are written as the effective user, rather than root.  Squid
     * may take on root privs during reconfigure.  If squid.conf
     * contains a "Bungled" line, fatal() will be called when the
     * process still has root privs.
     */
    leave_suid();

    if (opt_catch_signals)
        storeDirWriteCleanLogs(0);

    abort();
}

void
debug_trap(const char *message) {
    if (!opt_catch_signals)
        fatal_dump(message);

    _db_print("WARNING: %s\n", message);
}

void
sig_child(int sig) {
#ifndef _SQUID_MSWIN_
#ifdef _SQUID_NEXT_
    union wait status;
#else

    int status;
#endif

    pid_t pid;

    do {
#ifdef _SQUID_NEXT_
        pid = wait3(&status, WNOHANG, NULL);
#else

        pid = waitpid(-1, &status, WNOHANG);
#endif
        /* no debug() here; bad things happen if the signal is delivered during _db_print() */
#if HAVE_SIGACTION

    } while (pid > 0);

#else

    }

    while (pid > 0 || (pid < 0 && errno == EINTR))

        ;
    signal(sig, sig_child);

#endif
#endif
}

const char *
getMyHostname(void)
{
    LOCAL_ARRAY(char, host, SQUIDHOSTNAMELEN + 1);
    static int present = 0;

    const struct hostent *h = NULL;

    struct IN_ADDR sa;

    if (Config.visibleHostname != NULL)
        return Config.visibleHostname;

    if (present)
        return host;

    host[0] = '\0';

    memcpy(&sa, &any_addr, sizeof(sa));

    if (Config.Sockaddr.http && sa.s_addr == any_addr.s_addr)
        memcpy(&sa, &Config.Sockaddr.http->s.sin_addr, sizeof(sa));

#if USE_SSL

    if (Config.Sockaddr.https && sa.s_addr == any_addr.s_addr)
        memcpy(&sa, &Config.Sockaddr.https->http.s.sin_addr, sizeof(sa));

#endif
    /*
     * If the first http_port address has a specific address, try a
     * reverse DNS lookup on it.
     */
    if (sa.s_addr != any_addr.s_addr) {
        h = gethostbyaddr((char *) &sa,
                          sizeof(sa), AF_INET);

        if (h != NULL) {
            /* DNS lookup successful */
            /* use the official name from DNS lookup */
            xstrncpy(host, h->h_name, SQUIDHOSTNAMELEN);
            debugs(50, 4, "getMyHostname: resolved " << inet_ntoa(sa) << " to '" << host << "'");

            present = 1;

            if (strchr(host, '.'))
                return host;

        }

        debugs(50, 1, "WARNING: failed to resolve " << inet_ntoa(sa) << " to a fully qualified hostname");
    }

    /*
     * Get the host name and store it in host to return
     */
    if (gethostname(host, SQUIDHOSTNAMELEN) < 0) {
        debugs(50, 1, "WARNING: gethostname failed: " << xstrerror());
    } else if ((h = gethostbyname(host)) == NULL) {
        debugs(50, 1, "WARNING: gethostbyname failed for " << host);
    } else {
        debugs(50, 6, "getMyHostname: '" << host << "' resolved into '" << h->h_name << "'");
        /* DNS lookup successful */
        /* use the official name from DNS lookup */
        xstrncpy(host, h->h_name, SQUIDHOSTNAMELEN);
        present = 1;

        if (strchr(host, '.'))
            return host;
    }

    if (opt_send_signal == -1)
        fatal("Could not determine fully qualified hostname.  Please set 'visible_hostname'\n");
    else
        return ("localhost");

    return NULL;		/* keep compiler happy */
}

const char *
uniqueHostname(void)
{
    return Config.uniqueHostname ? Config.uniqueHostname : getMyHostname();
}

/* leave a privilegied section. (Give up any privilegies)
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

        if (setgid(Config2.effectiveGroupID) < 0)
            debugs(50, 0, "ALERT: setgid: " << xstrerror());

    }

    if (geteuid() != 0)
        return;

    /* Started as a root, check suid option */
    if (Config.effectiveUser == NULL)
        return;

    debugs(21, 3, "leave_suid: PID " << getpid() << " giving up root, becoming '" << Config.effectiveUser << "'");

    if (!Config.effectiveGroup) {

        if (setgid(Config2.effectiveGroupID) < 0)
            debugs(50, 0, "ALERT: setgid: " << xstrerror());

        if (initgroups(Config.effectiveUser, Config2.effectiveGroupID) < 0) {
            debugs(50, 0, "ALERT: initgroups: unable to set groups for User " <<
                   Config.effectiveUser << " and Group " <<
                   (unsigned) Config2.effectiveGroupID << "");
        }
    }

#if HAVE_SETRESUID

    if (setresuid(Config2.effectiveUserID, Config2.effectiveUserID, 0) < 0)
        debugs(50, 0, "ALERT: setresuid: " << xstrerror());

#elif HAVE_SETEUID

    if (seteuid(Config2.effectiveUserID) < 0)
        debugs(50, 0, "ALERT: seteuid: " << xstrerror());

#else

    if (setuid(Config2.effectiveUserID) < 0)
        debugs(50, 0, "ALERT: setuid: " << xstrerror());

#endif

    restoreCapabilities(1);

#if HAVE_PRCTL && defined(PR_SET_DUMPABLE)
    /* Set Linux DUMPABLE flag */
    if (Config.coredump_dir && prctl(PR_SET_DUMPABLE, 1) != 0)
        debugs(50, 2, "ALERT: prctl: " << xstrerror());

#endif
}

/* Enter a privilegied section */
void
enter_suid(void)
{
    debugs(21, 3, "enter_suid: PID " << getpid() << " taking root priveleges");
#if HAVE_SETRESUID

    setresuid((uid_t)-1, 0, (uid_t)-1);
#else

    setuid(0);
#endif
#if HAVE_PRCTL && defined(PR_SET_DUMPABLE)
    /* Set Linux DUMPABLE flag */

    if (Config.coredump_dir && prctl(PR_SET_DUMPABLE, 1) != 0)
        debugs(50, 2, "ALERT: prctl: " << xstrerror());

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

    setuid(0);

    if (setuid(uid) < 0)
        debugs(50, 1, "no_suid: setuid: " << xstrerror());

    restoreCapabilities(0);

#if HAVE_PRCTL && defined(PR_SET_DUMPABLE)
    /* Set Linux DUMPABLE flag */
    if (Config.coredump_dir && prctl(PR_SET_DUMPABLE, 1) != 0)
        debugs(50, 2, "ALERT: prctl: " << xstrerror());

#endif
}

void
writePidFile(void)
{
    int fd;
    const char *f = NULL;
    mode_t old_umask;
    char buf[32];

    if ((f = Config.pidFilename) == NULL)
        return;

    if (!strcmp(Config.pidFilename, "none"))
        return;

    enter_suid();

    old_umask = umask(022);

    fd = file_open(f, O_WRONLY | O_CREAT | O_TRUNC | O_TEXT);

    umask(old_umask);

    leave_suid();

    if (fd < 0) {
        debugs(50, 0, "" << f << ": " << xstrerror());
        debug_trap("Could not write pid file");
        return;
    }

    snprintf(buf, 32, "%d\n", (int) getpid());
    FD_WRITE_METHOD(fd, buf, strlen(buf));
    file_close(fd);
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
        fprintf(stderr, "%s: ERROR: No pid file name defined\n", appname);
        exit(1);
    }

    if (Config.chroot_dir && geteuid() == 0) {
        int len = strlen(Config.chroot_dir) + 1 + strlen(f) + 1;
        chroot_f = (char *)xmalloc(strlen(Config.chroot_dir) + 1 + strlen(f) + 1);
        snprintf(chroot_f, len, "%s/%s", Config.chroot_dir, f);
        f = chroot_f;
    }

    pid_fp = fopen(f, "r");

    if (pid_fp != NULL) {
        pid = 0;

        if (fscanf(pid_fp, "%d", &i) == 1)
            pid = (pid_t) i;

        fclose(pid_fp);
    } else {
        if (errno != ENOENT) {
            fprintf(stderr, "%s: ERROR: Could not read pid file\n", appname);
            fprintf(stderr, "\t%s: %s\n", f, xstrerror());
            exit(1);
        }
    }

    safe_free(chroot_f);
    return pid;
}


void
setMaxFD(void)
{
#if HAVE_SETRLIMIT
    /* try to use as many file descriptors as possible */
    /* System V uses RLIMIT_NOFILE and BSD uses RLIMIT_OFILE */

    struct rlimit rl;
#if defined(RLIMIT_NOFILE)

    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        debugs(50, 0, "setrlimit: RLIMIT_NOFILE: " << xstrerror());
    } else {
        rl.rlim_cur = Squid_MaxFD;

        if (rl.rlim_cur > rl.rlim_max)
            Squid_MaxFD = rl.rlim_cur = rl.rlim_max;

        if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
            snprintf(tmp_error_buf, ERROR_BUF_SZ,
                     "setrlimit: RLIMIT_NOFILE: %s", xstrerror());
            fatal_dump(tmp_error_buf);
        }
    }

#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, &rl) < 0) {
        debugs(50, 0, "setrlimit: RLIMIT_NOFILE: " << xstrerror());
    } else {
        rl.rlim_cur = Squid_MaxFD;

        if (rl.rlim_cur > rl.rlim_max)
            Squid_MaxFD = rl.rlim_cur = rl.rlim_max;

        if (setrlimit(RLIMIT_OFILE, &rl) < 0) {
            snprintf(tmp_error_buf, ERROR_BUF_SZ,
                     "setrlimit: RLIMIT_OFILE: %s", xstrerror());
            fatal_dump(tmp_error_buf);
        }
    }

#endif
#else /* HAVE_SETRLIMIT */
    debugs(21, 1, "setMaxFD: Cannot increase: setrlimit() not supported on this system");

#endif /* HAVE_SETRLIMIT */

#if HAVE_SETRLIMIT && defined(RLIMIT_DATA)

    if (getrlimit(RLIMIT_DATA, &rl) < 0) {
        debugs(50, 0, "getrlimit: RLIMIT_DATA: " << xstrerror());
    } else if (rl.rlim_max > rl.rlim_cur) {
        rl.rlim_cur = rl.rlim_max;	/* set it to the max */

        if (setrlimit(RLIMIT_DATA, &rl) < 0) {
            snprintf(tmp_error_buf, ERROR_BUF_SZ,
                     "setrlimit: RLIMIT_DATA: %s", xstrerror());
            fatal_dump(tmp_error_buf);
        }
    }

#endif /* RLIMIT_DATA */
#if HAVE_SETRLIMIT && defined(RLIMIT_VMEM)
    if (getrlimit(RLIMIT_VMEM, &rl) < 0) {
        debugs(50, 0, "getrlimit: RLIMIT_VMEM: " << xstrerror());
    } else if (rl.rlim_max > rl.rlim_cur) {
        rl.rlim_cur = rl.rlim_max;	/* set it to the max */

        if (setrlimit(RLIMIT_VMEM, &rl) < 0) {
            snprintf(tmp_error_buf, ERROR_BUF_SZ,
                     "setrlimit: RLIMIT_VMEM: %s", xstrerror());
            fatal_dump(tmp_error_buf);
        }
    }

#endif /* RLIMIT_VMEM */
}

int
percent(int a, int b)
{
    return b ? ((int) (100.0 * a / b + 0.5)) : 0;
}

double
dpercent(double a, double b)
{
    return b ? (100.0 * a / b) : 0.0;
}

void
squid_signal(int sig, SIGHDLR * func, int flags)
{
#if HAVE_SIGACTION

    struct sigaction sa;
    sa.sa_handler = func;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);

    if (sigaction(sig, &sa, NULL) < 0)
        debugs(50, 0, "sigaction: sig=" << sig << " func=" << func << ": " << xstrerror());

#else
#ifdef _SQUID_MSWIN_
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

struct IN_ADDR

            inaddrFromHostent(const struct hostent *hp)
{

    struct IN_ADDR s;
    xmemcpy(&s.s_addr, hp->h_addr, sizeof(s.s_addr));
    return s;
}

double
doubleAverage(double cur, double newD, int N, int max)
{
    if (N > max)
        N = max;

    return (cur * (N - 1.0) + newD) / N;
}

int
intAverage(int cur, int newI, int n, int max)
{
    if (n > max)
        n = max;

    return (cur * (n - 1) + newI) / n;
}

void
logsFlush(void)
{
    if (debug_log)
        fflush(debug_log);
}

dlink_node *
dlinkNodeNew()
{
    if (dlink_node_pool == NULL)
        dlink_node_pool = memPoolCreate("Dlink list nodes", sizeof(dlink_node));

    /* where should we call delete dlink_node_pool;dlink_node_pool = NULL; */
    return (dlink_node *)dlink_node_pool->alloc();
}

/* the node needs to be unlinked FIRST */
void
dlinkNodeDelete(dlink_node * m)
{
    if (m == NULL)
        return;

    dlink_node_pool->free(m);
}

void
dlinkAdd(void *data, dlink_node * m, dlink_list * list)
{
    m->data = data;
    m->prev = NULL;
    m->next = list->head;

    if (list->head)
        list->head->prev = m;

    list->head = m;

    if (list->tail == NULL)
        list->tail = m;
}

void
dlinkAddAfter(void *data, dlink_node * m, dlink_node * n, dlink_list * list)
{
    m->data = data;
    m->prev = n;
    m->next = n->next;

    if (n->next)
        n->next->prev = m;
    else {
        assert(list->tail == n);
        list->tail = m;
    }

    n->next = m;
}

void
dlinkAddTail(void *data, dlink_node * m, dlink_list * list)
{
    m->data = data;
    m->next = NULL;
    m->prev = list->tail;

    if (list->tail)
        list->tail->next = m;

    list->tail = m;

    if (list->head == NULL)
        list->head = m;
}

void
dlinkDelete(dlink_node * m, dlink_list * list)
{
    if (m->next)
        m->next->prev = m->prev;

    if (m->prev)
        m->prev->next = m->next;

    if (m == list->head)
        list->head = m->next;

    if (m == list->tail)
        list->tail = m->prev;

    m->next = m->prev = NULL;
}

void
kb_incr(kb_t * k, size_t v)
{
    k->bytes += v;
    k->kb += (k->bytes >> 10);
    k->bytes &= 0x3FF;
}

void
debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm)
{
    MemBuf mb;
    Packer p;
    assert(label && obj && pm);
    mb.init();
    packerToMemInit(&p, &mb);
    (*pm) (obj, &p);
    debugs(section, level, "" << label << "" << mb.buf << "");
    packerClean(&p);
    mb.clean();
}

void
parseEtcHosts(void)
{
    FILE *fp;
    char buf[1024];
    char buf2[512];
    char *nt = buf;
    char *lt = buf;

    if (NULL == Config.etcHostsPath)
        return;

    if (0 == strcmp(Config.etcHostsPath, "none"))
        return;

    fp = fopen(Config.etcHostsPath, "r");

    if (fp == NULL) {
        debugs(1, 1, "parseEtcHosts: " << Config.etcHostsPath << ": " << xstrerror());
        return;
    }

#ifdef _SQUID_WIN32_
    setmode(fileno(fp), O_TEXT);

#endif

    while (fgets(buf, 1024, fp)) {	/* for each line */
        wordlist *hosts = NULL;
        char *addr;

        if (buf[0] == '#')	/* MS-windows likes to add comments */
            continue;

        strtok(buf, "#");	/* chop everything following a comment marker */

        lt = buf;

        addr = buf;

        debugs(1, 5, "etc_hosts: line is '" << buf << "'");

        nt = strpbrk(lt, w_space);

        if (nt == NULL)		/* empty line */
            continue;

        *nt = '\0';		/* null-terminate the address */

        debugs(1, 5, "etc_hosts: address is '" << addr << "'");

        lt = nt + 1;

        while ((nt = strpbrk(lt, w_space))) {
            char *host = NULL;

            if (nt == lt) {	/* multiple spaces */
                debugs(1, 5, "etc_hosts: multiple spaces, skipping");
                lt = nt + 1;
                continue;
            }

            *nt = '\0';
            debugs(1, 5, "etc_hosts: got hostname '" << lt << "'");

            if (Config.appendDomain && !strchr(lt, '.')) {
                /* I know it's ugly, but it's only at reconfig */
                strncpy(buf2, lt, 512);
                strncat(buf2, Config.appendDomain, 512 - strlen(lt) - 1);
                host = buf2;
            } else {
                host = lt;
            }

            if (ipcacheAddEntryFromHosts(host, addr) != 0)
                goto skip;	/* invalid address, continuing is useless */

            wordlistAdd(&hosts, host);

            lt = nt + 1;
        }

        fqdncacheAddEntryFromHosts(addr, hosts);

skip:
        wordlistDestroy(&hosts);
    }

    fclose (fp);
}

int
getMyPort(void)
{
    if (Config.Sockaddr.http)
        return ntohs(Config.Sockaddr.http->s.sin_port);

#if USE_SSL

    if (Config.Sockaddr.https)
        return ntohs(Config.Sockaddr.https->http.s.sin_port);

#endif

    fatal("No port defined");

    return 0;			/* NOT REACHED */
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

        switch(*str) {

        case '\n':
            mb->append("\\n", 2);
            str++;
            break;

        case '\r':
            mb->append("\\r", 2);
            str++;
            break;

        case '\0':
            break;

        default:
            mb->append("\\", 1);
            mb->append(str, 1);
            str++;
            break;
        }
    }

    if (quoted)
        mb->append("\"", 1);
}

void
keepCapabilities(void)
{
#if HAVE_PRCTL && defined(PR_SET_KEEPCAPS) && HAVE_SYS_CAPABILITY_H

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
        /* Silent failure unless TPROXY is required. Maybe not started as root */
#if LINUX_TPROXY

        if (need_linux_tproxy)
            debugs(1, 1, "Error - tproxy support requires capability setting which has failed.  Continuing without tproxy support");

        need_linux_tproxy = 0;

#endif

    }

#endif
}

static void
restoreCapabilities(int keep)
{
#if defined(_SQUID_LINUX_) && HAVE_SYS_CAPABILITY_H
    cap_user_header_t head = (cap_user_header_t) xcalloc(1, sizeof(cap_user_header_t));
    cap_user_data_t cap = (cap_user_data_t) xcalloc(1, sizeof(cap_user_data_t));

    head->version = _LINUX_CAPABILITY_VERSION;

    if (capget(head, cap) != 0) {
        debugs(50, 1, "Can't get current capabilities");
        goto nocap;
    }

    if (head->version != _LINUX_CAPABILITY_VERSION) {
        debugs(50, 1, "Invalid capability version " << head->version << " (expected " << _LINUX_CAPABILITY_VERSION << ")");
        goto nocap;
    }

    head->pid = 0;

    cap->inheritable = 0;
    cap->effective = (1 << CAP_NET_BIND_SERVICE);
#if LINUX_TPROXY

    if (need_linux_tproxy)
        cap->effective |= (1 << CAP_NET_ADMIN) | (1 << CAP_NET_BROADCAST);

#endif

    if (!keep)
        cap->permitted &= cap->effective;

    if (capset(head, cap) != 0) {
        /* Silent failure unless TPROXY is required */
#if LINUX_TPROXY

        if (need_linux_tproxy)
            debugs(50, 1, "Error enabling needed capabilities. Will continue without tproxy support");

        need_linux_tproxy = 0;

#endif

    }

nocap:
    xfree(head);
    xfree(cap);
#else
#if LINUX_TPROXY

    if (need_linux_tproxy)
        debugs(50, 1, "Missing needed capability support. Will continue without tproxy support");

    need_linux_tproxy = 0;

#endif

#endif
}
