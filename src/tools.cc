/* $Id: tools.cc,v 1.4 1996/03/22 17:48:07 wessels Exp $ */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>		/* for sysconf() stuff */
#include <malloc.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/param.h>		/* has NOFILE */
#include <sys/types.h>

#include "debug.h"
#include "cache_cf.h"
#include "autoconf.h"
#include "ftp.h"		/* sig_child() needs to know FTP threads */


void death(), deathb(), neighbors_rotate_log(), stat_rotate_log();
void mail_warranty(), print_warranty(), _db_rotate_log();
int do_mallinfo = 0;		/* don't do mallinfo() unless this gets set */
int PrintRusage _PARAMS((void (*)(), FILE *));

extern ftpget_thread *FtpgetThread;
extern int catch_signals;	/* main.c */
extern int storeWriteCleanLog _PARAMS((void));

/*-------------------------------------------------------------------------
--
--  death, deathb
--
--  Function: These functions catch and report fatal system violations.
--
--  Inputs:   None.
--
--  Output:   None.
--
--  Comments: None.
--
--------------------------------------------------------------------------*/
void death()
{
    fprintf(stderr, "FATAL: Received Segment Violation...dying.\n");
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    storeWriteCleanLog();
    PrintRusage(NULL, stderr);
    print_warranty();
    abort();
}


void deathb()
{
    fprintf(stderr, "FATAL: Received bus error...dying.\n");
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    storeWriteCleanLog();
    PrintRusage(NULL, stderr);
    print_warranty();
    abort();
}

#define DEAD_MSG "\
The Harvest Cache (version %s) died.\n\
\n\
You've encountered a fatal error in the Harvest Cache version %s.\n\
If a core file was created (possibly in the swap directory),\n\
please execute 'gdb cached core' or 'dbx cached core', then type 'where',\n\
and report the trace back to harvest-dvl@cs.colorado.edu.\n\
\n\
Thanks!\n"

static char *dead_msg()
{
    static char msg[1024];
    sprintf(msg, DEAD_MSG, SQUID_VERSION, SQUID_VERSION);
    return msg;
}

void mail_warranty()
{
    FILE *fp;
    static char filename[256];
    static char command[256];

    sprintf(filename, "/tmp/mailin%d", (int) getpid());
    fp = fopen(filename, "w");
    if (fp != NULL) {
	fprintf(fp, "From: cached\n");
	fprintf(fp, "To: %s\n", getAdminEmail());
	fprintf(fp, "Subject: %s\n", dead_msg());
	fclose(fp);

	sprintf(command, "mail %s < %s", getAdminEmail(), filename);

	system(command);
	unlink(filename);
    }
}

void print_warranty()
{
    if (getAdminEmail())
	mail_warranty();
    else
	puts(dead_msg());
}

void rotate_logs(sig)
     int sig;
{
    debug(1, "rotate_logs: SIGHUP received.\n");

    storeWriteCleanLog();
    neighbors_rotate_log();
    stat_rotate_log();
    _db_rotate_log();
#if defined(_SQUID_SYSV_SIGNALS_)
    signal(sig, rotate_logs);
#endif
}

void shut_down(sig)
     int sig;
{
    debug(1, "Shutting down...\n");
    storeWriteCleanLog();
    PrintRusage(NULL, stderr);
    debug(0, "Harvest Cache (Version %s): Exiting due to signal %d.\n",
	SQUID_VERSION, sig);
    exit(1);
}

void fatal_common(message)
     char *message;
{
    if (syslog_enable)
	syslog(LOG_ALERT, message);
    fprintf(stderr, "FATAL: %s\n", message);
    fprintf(stderr, "Harvest Cache (Version %s): Terminated abnormally.\n",
	SQUID_VERSION);
    fflush(stderr);
    PrintRusage(NULL, stderr);
    if (debug_log != stderr) {
	debug(0, "FATAL: %s\n", message);
	debug(0, "Harvest Cache (Version %s): Terminated abnormally.\n",
	    SQUID_VERSION);
    }
}

/* fatal */
void fatal(message)
     char *message;
{
    fatal_common(message);
    exit(1);
}

/* fatal with dumping core */
void fatal_dump(message)
     char *message;
{
    if (message)
	fatal_common(message);
    if (catch_signals)
	storeWriteCleanLog();
    abort();
}


void dumpMallocStats(f)
     FILE *f;
{
#if USE_MALLINFO
    struct mallinfo mp;

    if (!do_mallinfo)
	return;

    mp = mallinfo();

    fprintf(f, "Malloc Instrumentation via mallinfo(): \n");
    fprintf(f, "   total space in arena  %d\n", mp.arena);
    fprintf(f, "   number of ordinary blocks  %d\n", mp.ordblks);
    fprintf(f, "   number of small blocks  %d\n", mp.smblks);
    fprintf(f, "   number of holding blocks  %d\n", mp.hblks);
    fprintf(f, "   space in holding block headers  %d\n", mp.hblkhd);
    fprintf(f, "   space in small blocks in use  %d\n", mp.usmblks);
    fprintf(f, "   space in free blocks  %d\n", mp.fsmblks);
    fprintf(f, "   space in ordinary blocks in use  %d\n", mp.uordblks);
    fprintf(f, "   space in free ordinary blocks  %d\n", mp.fordblks);
    fprintf(f, "   cost of enabling keep option  %d\n", mp.keepcost);
#if LNG_MALLINFO
    fprintf(f, "   max size of small blocks  %d\n", mp.mxfast);
    fprintf(f, "   number of small blocks in a holding block  %d\n",
	mp.nlblks);
    fprintf(f, "   small block rounding factor  %d\n", mp.grain);
    fprintf(f, "   space (including overhead) allocated in ord. blks  %d\n",
	mp.uordbytes);
    fprintf(f, "   number of ordinary blocks allocated  %d\n",
	mp.allocated);
    fprintf(f, "   bytes used in maintaining the free tree  %d\n",
	mp.treeoverhead);
#endif /* LNG_MALLINFO */

#if PRINT_MMAP
    mallocmap();
#endif /* PRINT_MMAP */
#endif /* USE_MALLINFO */
}

int PrintRusage(f, lf)
     void (*f) ();
     FILE *lf;
{
#if defined(HAVE_RUSAGE) && defined(RUSAGE_SELF)
    struct rusage rusage;

    getrusage(RUSAGE_SELF, &rusage);
    fprintf(lf, "CPU Usage: user %d sys %d\nMemory Usage: rss %d KB\n",
	rusage.ru_utime.tv_sec, rusage.ru_stime.tv_sec,
	rusage.ru_maxrss * getpagesize() / 1000);
    fprintf(lf, "Page faults with physical i/o: %d\n",
	rusage.ru_majflt);

#endif
    dumpMallocStats(lf);
    if (f)
	f(0);
    return 0;
}

int getHeapSize()
{
#if USE_MALLINFO
    struct mallinfo mp;

    mp = mallinfo();

    return (mp.arena);
#else
    return (0);
#endif
}

void sig_child(sig)
     int sig;
{
    int status;
    int pid;
    ftpget_thread *t = NULL;

    if ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
	debug(3, "sig_child: Ate pid %d\n", pid);
	for (t = FtpgetThread; t; t = t->next) {
	    debug(5, "sig_child: checking pid=%d  state=%d\n",
		t->pid, t->state);
	    if (t->pid == pid && t->state == FTPGET_THREAD_RUNNING) {
		debug(5, "sig_child: GOT IT!\n");
		t->state = FTPGET_THREAD_WAITED;
		t->status = status;
		t->wait_retval = pid;
		break;
	    }
	}
    }
#if defined(_SQUID_SYSV_SIGNALS_)
    signal(sig, sig_child);
#endif
}

#define MAX_ZOMBIES_TO_KILL 20
void kill_zombie()
{
    int status;
    int i = 0;
    int pid;

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
	debug(3, "kill_zombie: Ate pid %d\n", pid);
	if (++i > MAX_ZOMBIES_TO_KILL)
	    break;
    }
}

/*
 *  getMaxFD - returns the file descriptor table size
 */
int getMaxFD()
{
    static int i = -1;

    if (i == -1) {
#if defined(HAVE_SYSCONF) && defined(_SC_OPEN_MAX)
	i = sysconf(_SC_OPEN_MAX);	/* prefered method */
#elif defined(HAVE_GETDTABLESIZE)
	i = getdtablesize();	/* the BSD way */
#elif defined(OPEN_MAX)
	i = OPEN_MAX;
#elif defined(NOFILE)
	i = NOFILE;
#elif defined(_NFILE)
	i = _NFILE;
#else
	i = 64;			/* 64 is a safe default */
#endif
	debug(10, "getMaxFD set MaxFD at %d\n", i);
    }
    return (i);
}
