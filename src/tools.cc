
/* $Id: tools.cc,v 1.8 1996/03/27 04:42:10 wessels Exp $ */

#include "squid.h"

int do_mallinfo = 0;		/* don't do mallinfo() unless this gets set */

static int PrintRusage _PARAMS((void (*)(), FILE *));

extern int gethostname _PARAMS((char *name, int namelen));

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

void death(sig)
	int sig;
{
    if (sig == SIGSEGV)
    	fprintf(stderr, "FATAL: Received Segment Violation...dying.\n");
    else if (sig == SIGBUS)
        fprintf(stderr, "FATAL: Received bus error...dying.\n");
    else
        fprintf(stderr, "FATAL: Received signal %d...dying.\n", sig);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(sig, SIG_DFL);
    storeWriteCleanLog();
    PrintRusage(NULL, stderr);
    print_warranty();
    abort();
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

    if ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	debug(3, "sig_child: Ate pid %d\n", pid);

#if defined(_SQUID_SYSV_SIGNALS_)
    signal(sig, sig_child);
#endif
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

char *getMyHostname()
{
    static char host[SQUIDHOSTNAMELEN + 1];
    static int present = 0;
    struct hostent *h = NULL;

    /* Get the host name and store it in host to return */
    if (!present) {
	host[0] = '\0';
	if (gethostname(host, SQUIDHOSTNAMELEN) == -1) {
	    debug(1, "comm_hostname: gethostname failed: %s\n",
		xstrerror());
	    return NULL;
	} else {
	    if ((h = ipcache_gethostbyname(host)) != NULL) {
		/* DNS lookup successful */
		/* use the official name from DNS lookup */
		strcpy(host, h->h_name);
	    }
	    present = 1;
	}
    }
    return host;
}

int safeunlink(s, quiet)
     char *s;
     int quiet;
{
    int err;
    if ((err = unlink(s)) < 0)
	if (!quiet)
	    debug(1, "safeunlink: Couldn't delete %s. %s\n", s, xstrerror());
    return (err);
}
