
/*
 * $Id: tools.cc,v 1.80 1996/11/04 18:13:11 wessels Exp $
 *
 * DEBUG: section 21    Misc Functions
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

int do_mallinfo = 0;		/* don't do mallinfo() unless this gets set */
time_t squid_curtime;
struct timeval current_time;

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

#ifdef _SQUID_SOLARIS_
int getrusage _PARAMS((int, struct rusage *));
int getpagesize _PARAMS((void));
int gethostname _PARAMS((char *, int));
#endif

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
dumpMallocStats(FILE * f)
{
#if HAVE_MALLINFO
    struct mallinfo mp;
    int t;
    if (!do_mallinfo)
	return;
    mp = mallinfo();
    fprintf(f, "Memory usage for %s via mallinfo():\n", appname);
    fprintf(f, "\ttotal space in arena:  %6d KB\n",
	mp.arena >> 10);
    fprintf(f, "\tOrdinary blocks:       %6d KB %6d blks\n",
	mp.uordblks >> 10, mp.ordblks);
    fprintf(f, "\tSmall blocks:          %6d KB %6d blks\n",
	mp.usmblks >> 10, mp.smblks);
    fprintf(f, "\tHolding blocks:        %6d KB %6d blks\n",
	mp.hblkhd >> 10, mp.hblks);
    fprintf(f, "\tFree Small blocks:     %6d KB\n",
	mp.fsmblks >> 10);
    fprintf(f, "\tFree Ordinary blocks:  %6d KB\n",
	mp.fordblks >> 10);
    t = mp.uordblks + mp.usmblks + mp.hblkhd;
    fprintf(f, "\tTotal in use:          %6d KB %d%%\n",
	t >> 10, percent(t, mp.arena));
    t = mp.fsmblks + mp.fordblks;
    fprintf(f, "\tTotal free:            %6d KB %d%%\n",
	t >> 10, percent(t, mp.arena));
#ifdef WE_DONT_USE_KEEP
    fprintf(f, "\tKeep option:           %6d KB\n",
	mp.keepcost >> 10);
#endif
#if HAVE_EXT_MALLINFO
    fprintf(f, "\tmax size of small blocks:\t%d\n",
	mp.mxfast);
    fprintf(f, "\tnumber of small blocks in a holding block:\t%d\n",
	mp.nlblks);
    fprintf(f, "\tsmall block rounding factor:\t%d\n",
	mp.grain);
    fprintf(f, "\tspace (including overhead) allocated in ord. blks:\t%d\n",
	mp.uordbytes);
    fprintf(f, "\tnumber of ordinary blocks allocated:\t%d\n",
	mp.allocated);
    fprintf(f, "\tbytes used in maintaining the free tree:\t%d\n",
	mp.treeoverhead);
#endif /* HAVE_EXT_MALLINFO */
#if PRINT_MMAP
    mallocmap();
#endif /* PRINT_MMAP */
#endif /* HAVE_MALLINFO */
}

static int
PrintRusage(void (*f) (void), FILE * lf)
{
#if HAVE_GETRUSAGE && defined(RUSAGE_SELF)
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    fprintf(lf, "CPU Usage: user %d sys %d\n",
	(int) rusage.ru_utime.tv_sec, (int) rusage.ru_stime.tv_sec);
#ifdef _SQUID_SGI_
    fprintf(lf, "Memory Usage: rss %ld KB\n", rusage.ru_maxrss);
#else
    fprintf(lf, "Memory Usage: rss %ld KB\n",
	(rusage.ru_maxrss * getpagesize()) >> 10);
#endif /* _SQUID_SGI_ */
    fprintf(lf, "Page faults with physical i/o: %ld\n",
	rusage.ru_majflt);
#endif /* HAVE_GETRUSAGE */
    dumpMallocStats(lf);
    if (f)
	f();
    return 0;
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
#if SA_RESETHAND == 0
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(sig, SIG_DFL);
#endif
    /* Release the main ports as early as possible */
    if (theHttpConnection >= 0)
	(void) close(theHttpConnection);
    if (theInIcpConnection >= 0)
	(void) close(theInIcpConnection);
    storeWriteCleanLog();
    PrintRusage(NULL, debug_log);
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
    debug(21, 1, "sigusr2_handle: SIGUSR2 received.\n");
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

void
setSocketShutdownLifetimes(int lft)
{
    FD_ENTRY *f = NULL;
    int cur;
    int i;
    for (i = fdstat_biggest_fd(); i >= 0; i--) {
	f = &fd_table[i];
	if (!f->read_handler && !f->write_handler)
	    continue;
	if (fdstatGetType(i) != FD_SOCKET)
	    continue;
	cur = comm_get_fd_lifetime(i);
	if (cur > 0 && (cur - squid_curtime) <= lft)
	    continue;
	comm_set_fd_lifetime(i, lft);
    }
}

void
normal_shutdown(void)
{
    debug(21, 1, "Shutting down...\n");
    if (Config.pidFilename) {
	enter_suid();
	safeunlink(Config.pidFilename, 0);
	leave_suid();
    }
    storeWriteCleanLog();
    PrintRusage(NULL, debug_log);
    storeCloseLog();
    statCloseLog();
    configFreeMemory();
    diskFreeMemory();
    storeFreeMemory();
    commFreeMemory();
    filemapFreeMemory();
    dnsFreeMemory();
    redirectFreeMemory();
    fdstatFreeMemory();
    errorpageFreeMemory();
    stmemFreeMemory();
    netdbFreeMemory();
    ipcacheFreeMemory();
    fqdncacheFreeMemory();
    debug(21, 0, "Squid Cache (Version %s): Exiting normally.\n",
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
    fprintf(debug_log, "Squid Cache (Version %s): Terminated abnormally.\n",
	version_string);
    fflush(debug_log);
    PrintRusage(NULL, debug_log);
}

/* fatal */
void
fatal(const char *message)
{
    fatal_common(message);
    exit(1);
}

/* fatal with dumping core */
void
fatal_dump(const char *message)
{
    if (message)
	fatal_common(message);
    if (opt_catch_signals)
	storeWriteCleanLog();
    abort();
}

/* fatal with dumping core */
void
_debug_trap(const char *message)
{
    if (!opt_catch_signals)
	fatal_dump(message);
    _db_print(0, 0, "WARNING: %s\n", message);
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
	debug(21, 3, "sig_child: Ate pid %d\n", pid);
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
	    debug(21, 1, "getMyHostname: gethostname failed: %s\n",
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

int
safeunlink(const char *s, int quiet)
{
    int err;
    if ((err = unlink(s)) < 0)
	if (!quiet)
	    debug(21, 1, "safeunlink: Couldn't delete %s. %s\n", s, xstrerror());
    return (err);
}

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
    debug(21, 3, "leave_suid: PID %d called\n", getpid());
    if (geteuid() != 0)
	return;
    /* Started as a root, check suid option */
    if (Config.effectiveUser == NULL)
	return;
    if ((pwd = getpwnam(Config.effectiveUser)) == NULL)
	return;
    if (Config.effectiveGroup && (grp = getgrnam(Config.effectiveGroup))) {
	setgid(grp->gr_gid);
    } else {
	setgid(pwd->pw_gid);
    }
    debug(21, 3, "leave_suid: PID %d giving up root, becoming '%s'\n",
	getpid(), pwd->pw_name);
#if HAVE_SETRESUID
    setresuid(pwd->pw_uid, pwd->pw_uid, 0);
#elif HAVE_SETEUID
    seteuid(pwd->pw_uid);
#else
    setuid(pwd->pw_uid);
#endif
}

/* Enter a privilegied section */
void
enter_suid(void)
{
    debug(21, 3, "enter_suid: PID %d taking root priveleges\n", getpid());
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
    debug(21, 3, "leave_suid: PID %d giving up root priveleges forever\n", getpid());
#if HAVE_SETRESUID
    setresuid(uid, uid, uid);
#else
    setuid(0);
    setuid(uid);
#endif
}

void
writePidFile(void)
{
    FILE *pid_fp = NULL;
    char *f = NULL;

    if ((f = Config.pidFilename) == NULL)
	return;
    enter_suid();
    pid_fp = fopen(f, "w");
    leave_suid();
    if (pid_fp != NULL) {
	fprintf(pid_fp, "%d\n", (int) getpid());
	fclose(pid_fp);
    } else {
	debug(21, 0, "WARNING: Could not write pid file\n");
	debug(21, 0, "         %s: %s\n", f, xstrerror());
    }
}


pid_t
readPidFile(void)
{
    FILE *pid_fp = NULL;
    char *f = NULL;
    pid_t pid = -1;
    int i;

    if ((f = Config.pidFilename) == NULL) {
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
	debug(21, 0, "setrlimit: RLIMIT_NOFILE: %s\n", xstrerror());
    } else {
	rl.rlim_cur = FD_SETSIZE;
	if (rl.rlim_cur > rl.rlim_max)
	    rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_NOFILE: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, &rl) < 0) {
	debug(21, 0, "setrlimit: RLIMIT_NOFILE: %s\n", xstrerror());
    } else {
	rl.rlim_cur = FD_SETSIZE;
	if (rl.rlim_cur > rl.rlim_max)
	    rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_OFILE, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_OFILE: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif
#else /* HAVE_SETRLIMIT */
    debug(21, 1, "setMaxFD: Cannot increase: setrlimit() not supported on this system\n");
#endif /* HAVE_SETRLIMIT */

#if HAVE_SETRLIMIT && defined(RLIMIT_DATA)
    if (getrlimit(RLIMIT_DATA, &rl) < 0) {
	debug(21, 0, "getrlimit: RLIMIT_DATA: %s\n", xstrerror());
    } else {
	rl.rlim_cur = rl.rlim_max;	/* set it to the max */
	if (setrlimit(RLIMIT_DATA, &rl) < 0) {
	    sprintf(tmp_error_buf, "setrlimit: RLIMIT_DATA: %s", xstrerror());
	    fatal_dump(tmp_error_buf);
	}
    }
#endif /* RLIMIT_DATA */
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
	debug(1, 0, "sigaction: sig=%d func=%p: %s\n", sig, func, xstrerror());
#else
    (void) signal(sig, func);
#endif
}

struct in_addr
inaddrFromHostent(const struct hostent *hp)
{
    struct in_addr s;
    xmemcpy(&s.s_addr, hp->h_addr, sizeof(s.s_addr));
    return s;
}
