
/*
 * $Id: tools.cc,v 1.120 1997/08/25 22:36:03 wessels Exp $
 *
 * DEBUG: section 21    Misc Functions
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

#define DEAD_MSG "\
The Squid Cache (version %s) died.\n\
\n\
You've encountered a fatal error in the Squid Cache version %s.\n\
If a core file was created (possibly in the swap directory),\n\
please execute 'gdb squid core' or 'dbx squid core', then type 'where',\n\
and report the trace back to squid-bugs@nlanr.net.\n\
\n\
Thanks!\n"

static void fatal_common _PARAMS((const char *));
static void mail_warranty _PARAMS((void));
static void shutdownTimeoutHandler _PARAMS((int fd, void *data));

#if USE_ASYNC_IO
static void safeunlinkComplete _PARAMS((void *data, int retcode, int errcode));
#endif

#ifdef _SQUID_SOLARIS_
int getrusage _PARAMS((int, struct rusage *));
int getpagesize _PARAMS((void));
int gethostname _PARAMS((char *, int));
#endif

static void
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
    sprintf(msg, DEAD_MSG, version_string, version_string);
    return msg;
}

static void
mail_warranty(void)
{
    FILE *fp = NULL;
    char *filename;
    static char command[256];
    if ((filename = tempnam(NULL, appname)) == NULL)
	return;
    if ((fp = fopen(filename, "w")) == NULL)
	return;
    fprintf(fp, "From: %s\n", appname);
    fprintf(fp, "To: %s\n", Config.adminEmail);
    fprintf(fp, "Subject: %s\n", dead_msg());
    fclose(fp);
    sprintf(command, "mail %s < %s", Config.adminEmail, filename);
    system(command);		/* XXX should avoid system(3) */
    unlink(filename);
}

static void
dumpMallocStats(void)
{
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    struct mstats ms = mstats();
    fprintf(debug_log, "\ttotal space in arena:  %6d KB\n",
	ms.bytes_total >> 10);
    fprintf(debug_log, "\tTotal free:            %6d KB %d%%\n",
	ms.bytes_free >> 10,
	percent(ms.bytes_free, ms.bytes_total));
#elif HAVE_MALLINFO
    struct mallinfo mp;
    int t;
    if (!do_mallinfo)
	return;
    mp = mallinfo();
    fprintf(debug_log, "Memory usage for %s via mallinfo():\n", appname);
    fprintf(debug_log, "\ttotal space in arena:  %6d KB\n",
	mp.arena >> 10);
    fprintf(debug_log, "\tOrdinary blocks:       %6d KB %6d blks\n",
	mp.uordblks >> 10, mp.ordblks);
    fprintf(debug_log, "\tSmall blocks:          %6d KB %6d blks\n",
	mp.usmblks >> 10, mp.smblks);
    fprintf(debug_log, "\tHolding blocks:        %6d KB %6d blks\n",
	mp.hblkhd >> 10, mp.hblks);
    fprintf(debug_log, "\tFree Small blocks:     %6d KB\n",
	mp.fsmblks >> 10);
    fprintf(debug_log, "\tFree Ordinary blocks:  %6d KB\n",
	mp.fordblks >> 10);
    t = mp.uordblks + mp.usmblks + mp.hblkhd;
    fprintf(debug_log, "\tTotal in use:          %6d KB %d%%\n",
	t >> 10, percent(t, mp.arena));
    t = mp.fsmblks + mp.fordblks;
    fprintf(debug_log, "\tTotal free:            %6d KB %d%%\n",
	t >> 10, percent(t, mp.arena));
#if HAVE_EXT_MALLINFO
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
#endif /* HAVE_EXT_MALLINFO */
#endif /* HAVE_MALLINFO */
}

static void
PrintRusage(void)
{
#if HAVE_GETRUSAGE && defined(RUSAGE_SELF)
    struct rusage rusage;
#ifdef _SQUID_SOLARIS_
    /* Solaris 2.5 has getrusage() permission bug -- Arjan de Vet */
    enter_suid();
#endif
    getrusage(RUSAGE_SELF, &rusage);
#ifdef _SQUID_SOLARIS_
    leave_suid();
#endif
    fprintf(debug_log, "CPU Usage: user %d sys %d\n",
	(int) rusage.ru_utime.tv_sec, (int) rusage.ru_stime.tv_sec);
#if defined(_SQUID_SGI_) || defined(_SQUID_OSF_) || defined(BSD4_4)
    fprintf(debug_log, "Maximum Resident Size: %ld KB\n", rusage.ru_maxrss);
#else /* _SQUID_SGI_ */
    fprintf(debug_log, "Maximum Resident Size: %ld KB\n",
	(rusage.ru_maxrss * getpagesize()) >> 10);
#endif /* _SQUID_SGI_ */
    fprintf(debug_log, "Page faults with physical i/o: %ld\n",
	rusage.ru_majflt);
#endif /* HAVE_GETRUSAGE */
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
#endif /* PRINT_STACK_TRACE */

#if SA_RESETHAND == 0
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(sig, SIG_DFL);
#endif
    releaseServerSockets();
    storeWriteCleanLogs(0);
    PrintRusage();
    dumpMallocStats();
    if (squid_curtime - SQUID_RELEASE_TIME < 864000) {
	/* skip if more than 10 days old */
	if (Config.adminEmail)
	    mail_warranty();
	else
	    puts(dead_msg());
    }
    abort();
}


void
sigusr2_handle(int sig)
{
    static int state = 0;
    /* no debug() here; bad things happen if the signal is delivered during _db_print() */
    if (state == 0) {
	_db_init(Config.Log.log, "ALL,10");
	state = 1;
    } else {
	_db_init(Config.Log.log, Config.debugOptions);
	state = 0;
    }
#if !HAVE_SIGACTION
    signal(sig, sigusr2_handle);	/* reinstall */
#endif
}

static void
shutdownTimeoutHandler(int fd, void *data)
{
    debug(21, 1) ("Forcing close of FD %d\n", fd);
    comm_close(fd);
}

void
setSocketShutdownLifetimes(int to)
{
    fde *f = NULL;
    int i;
    for (i = Biggest_FD; i >= 0; i--) {
	f = &fd_table[i];
	if (!f->read_handler && !f->write_handler)
	    continue;
	if (f->type != FD_SOCKET)
	    continue;
	if (f->timeout > 0 && (int) (f->timeout - squid_curtime) <= to)
	    continue;
	commSetTimeout(i,
	    to,
	    f->timeout_handler ? f->timeout_handler : shutdownTimeoutHandler,
	    f->timeout_data);
    }
}

void
normal_shutdown(void)
{
    debug(21, 1) ("Shutting down...\n");
    if (Config.pidFilename && strcmp(Config.pidFilename, "none")) {
	enter_suid();
	safeunlink(Config.pidFilename, 0);
	leave_suid();
    }
    releaseServerSockets();
    unlinkdClose();
    storeWriteCleanLogs(0);
    PrintRusage();
    dumpMallocStats();
    storeCloseLog();
    accessLogClose();
#if PURIFY
    configFreeMemory();
    storeFreeMemory();
    dnsFreeMemory();
    redirectFreeMemory();
    errorpageFreeMemory();
    stmemFreeMemory();
    netdbFreeMemory();
    ipcacheFreeMemory();
    fqdncacheFreeMemory();
#endif
    file_close(0);
    file_close(1);
    file_close(2);
    fdDumpOpen();
    fdFreeMemory();
    debug(21, 0) ("Squid Cache (Version %s): Exiting normally.\n",
	version_string);
    fclose(debug_log);
    exit(0);
}

static void
fatal_common(const char *message)
{
#if HAVE_SYSLOG
    if (opt_syslog_enable)
	syslog(LOG_ALERT, "%s", message);
#endif
    fprintf(debug_log, "FATAL: %s\n", message);
    if (opt_debug_stderr && debug_log != stderr)
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
    /* check for store_rebuilding flag because fatal() is often
     * used in early initialization phases, long before we ever
     * get to the store log. */
    if (!store_rebuilding)
	storeWriteCleanLogs(0);
    fatal_common(message);
    exit(1);
}

/* fatal with dumping core */
void
fatal_dump(const char *message)
{
    releaseServerSockets();
    if (message)
	fatal_common(message);
    if (opt_catch_signals)
	storeWriteCleanLogs(0);
    abort();
}

void
debug_trap(const char *message)
{
    if (!opt_catch_signals)
	fatal_dump(message);
    _db_level = 0;
    _db_print("WARNING: %s\n", message);
}

void
sig_child(int sig)
{
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
    } while (pid > 0 || (pid < 0 && errno == EINTR));
    signal(sig, sig_child);
#endif
}

const char *
getMyHostname(void)
{
    LOCAL_ARRAY(char, host, SQUIDHOSTNAMELEN + 1);
    static int present = 0;
    const struct hostent *h = NULL;
    char *t = NULL;

    if ((t = Config.visibleHostname))
	return t;

    /* Get the host name and store it in host to return */
    if (!present) {
	host[0] = '\0';
	if (gethostname(host, SQUIDHOSTNAMELEN) == -1) {
	    debug(50, 1) ("getMyHostname: gethostname failed: %s\n",
		xstrerror());
	    return NULL;
	} else {
	    if ((h = gethostbyname(host)) != NULL) {
		/* DNS lookup successful */
		/* use the official name from DNS lookup */
		strcpy(host, h->h_name);
	    }
	    present = 1;
	}
    }
    return host;
}

void
safeunlink(const char *s, int quiet)
{
#if USE_ASYNC_IO
    aioUnlink(s,
	quiet ? NULL : safeunlinkComplete,
	quiet ? NULL : xstrdup(s));
#else
    if (unlink(s) < 0 && !quiet)
	debug(50, 1) ("safeunlink: Couldn't delete %s: %s\n", s, xstrerror());
#endif
}

#if USE_ASYNC_IO
static void
safeunlinkComplete(void *data, int retcode, int errcode)
{
    char *s = data;
    if (retcode < 0) {
	errno = errcode;
	debug(50, 1) ("safeunlink: Couldn't delete %s. %s\n", s, xstrerror());
	errno = 0;
    }
    xfree(s);
}
#endif

/* leave a privilegied section. (Give up any privilegies)
 * Routines that need privilegies can rap themselves in enter_suid()
 * and leave_suid()
 * To give upp all posibilites to gain privilegies use no_suid()
 */
void
leave_suid(void)
{
    struct passwd *pwd = NULL;
    struct group *grp = NULL;
    debug(21, 3) ("leave_suid: PID %d called\n", getpid());
    if (geteuid() != 0)
	return;
    /* Started as a root, check suid option */
    if (Config.effectiveUser == NULL)
	return;
    if ((pwd = getpwnam(Config.effectiveUser)) == NULL)
	return;
    if (Config.effectiveGroup && (grp = getgrnam(Config.effectiveGroup))) {
	if (setgid(grp->gr_gid) < 0)
	    debug(50, 1) ("leave_suid: setgid: %s\n", xstrerror());
    } else {
	if (setgid(pwd->pw_gid) < 0)
	    debug(50, 1) ("leave_suid: setgid: %s\n", xstrerror());
    }
    debug(21, 3) ("leave_suid: PID %d giving up root, becoming '%s'\n",
	getpid(), pwd->pw_name);
#if HAVE_SETRESUID
    if (setresuid(pwd->pw_uid, pwd->pw_uid, 0) < 0)
	debug(50, 1) ("leave_suid: setresuid: %s\n", xstrerror());
#elif HAVE_SETEUID
    if (seteuid(pwd->pw_uid) < 0)
	debug(50, 1) ("leave_suid: seteuid: %s\n", xstrerror());
#else
    if (setuid(pwd->pw_uid) < 0)
	debug(50, 1) ("leave_suid: setuid: %s\n", xstrerror());
#endif
}

/* Enter a privilegied section */
void
enter_suid(void)
{
    debug(21, 3) ("enter_suid: PID %d taking root priveleges\n", getpid());
#if HAVE_SETRESUID
    setresuid(-1, 0, -1);
#else
    setuid(0);
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
    debug(21, 3) ("leave_suid: PID %d giving up root priveleges forever\n", getpid());
#if HAVE_SETRESUID
    if (setresuid(uid, uid, uid) < 0)
	debug(50, 1) ("no_suid: setresuid: %s\n", xstrerror());
#else
    setuid(0);
    if (setuid(uid) < 0)
	debug(50, 1) ("no_suid: setuid: %s\n", xstrerror());
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
    fd = file_open(f, O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL);
    umask(old_umask);
    leave_suid();
    if (fd < 0) {
	debug(50, 0) ("%s: %s\n", f, xstrerror());
	debug_trap("Could not write pid file");
	return;
    }
    sprintf(buf, "%d\n", (int) getpid());
    write(fd, buf, strlen(buf));
    file_close(fd);
}


pid_t
readPidFile(void)
{
    FILE *pid_fp = NULL;
    const char *f = Config.pidFilename;
    pid_t pid = -1;
    int i;

    if (f == NULL || !strcmp(Config.pidFilename, "none")) {
	fprintf(stderr, "%s: ERROR: No pid file name defined\n", appname);
	exit(1);
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
	debug(50, 0) ("setrlimit: RLIMIT_NOFILE: %s\n", xstrerror());
    } else {
	rl.rlim_cur = Squid_MaxFD;
	if (rl.rlim_cur > rl.rlim_max)
	    Squid_MaxFD = rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_NOFILE: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, &rl) < 0) {
	debug(50, 0) ("setrlimit: RLIMIT_NOFILE: %s\n", xstrerror());
    } else {
	rl.rlim_cur = Squid_MaxFD;
	if (rl.rlim_cur > rl.rlim_max)
	    Squid_MaxFD = rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_OFILE, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_OFILE: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif
#else /* HAVE_SETRLIMIT */
    debug(21, 1) ("setMaxFD: Cannot increase: setrlimit() not supported on this system\n");
#endif /* HAVE_SETRLIMIT */

#if HAVE_SETRLIMIT && defined(RLIMIT_DATA)
    if (getrlimit(RLIMIT_DATA, &rl) < 0) {
	debug(50, 0) ("getrlimit: RLIMIT_DATA: %s\n", xstrerror());
    } else if (rl.rlim_max > rl.rlim_cur) {
	rl.rlim_cur = rl.rlim_max;	/* set it to the max */
	if (setrlimit(RLIMIT_DATA, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_DATA: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif /* RLIMIT_DATA */
#if HAVE_SETRLIMIT && defined(RLIMIT_VMEM)
    if (getrlimit(RLIMIT_VMEM, &rl) < 0) {
	debug(50, 0) ("getrlimit: RLIMIT_VMEM: %s\n", xstrerror());
    } else if (rl.rlim_max > rl.rlim_cur) {
	rl.rlim_cur = rl.rlim_max;	/* set it to the max */
	if (setrlimit(RLIMIT_VMEM, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_VMEM: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif /* RLIMIT_VMEM */
}

time_t
getCurrentTime(void)
{
#if GETTIMEOFDAY_NO_TZP
    gettimeofday(&current_time);
#else
    gettimeofday(&current_time, NULL);
#endif
    return squid_curtime = current_time.tv_sec;
}

int
percent(int a, int b)
{
    return b ? ((int) (100.0 * a / b + 0.5)) : 0;
}

void
squid_signal(int sig, void (*func) _PARAMS((int)), int flags)
{
#if HAVE_SIGACTION
    struct sigaction sa;
    sa.sa_handler = func;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL) < 0)
	debug(50, 0) ("sigaction: sig=%d func=%p: %s\n", sig, func, xstrerror());
#else
    signal(sig, func);
#endif
}

struct in_addr
inaddrFromHostent(const struct hostent *hp)
{
    struct in_addr s;
    xmemcpy(&s.s_addr, hp->h_addr, sizeof(s.s_addr));
    return s;
}

double
doubleAverage(double cur, double new, int N, int max)
{
    if (N > max)
	N = max;
    return (cur * (N - 1.0) + new) / N;
}

int
intAverage(int cur, int new, int n, int max)
{
    if (n > max)
	n = max;
    return (cur * (n - 1)) + new / n;
}

void
logsFlush(void)
{
    if (debug_log)
	fflush(debug_log);
    if (cache_useragent_log)
	fflush(cache_useragent_log);
}

char *
checkNullString(char *p)
{
    return p ? p : "(NULL)";
}
