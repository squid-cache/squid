/*
 * $Id: main.cc,v 1.87 1996/09/24 20:17:31 wessels Exp $
 *
 * DEBUG: section 1     Startup and Main Loop
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

time_t squid_starttime = 0;
int theHttpConnection = -1;
int theInIcpConnection = -1;
int theOutIcpConnection = -1;
int do_reuse = 1;
int opt_unlink_on_reload = 0;
int opt_reload_hit_only = 0;	/* only UDP_HIT during store relaod */
int opt_catch_signals = 1;
int opt_dns_tests = 1;
int opt_foreground_rebuild = 0;
int opt_zap_disk_store = 0;
int opt_syslog_enable = 0;	/* disabled by default */
int opt_no_ipcache = 0;		/* use ipcache by default */
static int opt_send_signal = -1;	/* no signal to send */
int opt_udp_hit_obj = 1;
int opt_mem_pools = 1;
int opt_forwarded_for = 1;
int vhost_mode = 0;
volatile int unbuffered_logs = 1;	/* debug and hierarchy unbuffered by default */
volatile int shutdown_pending = 0;	/* set by SIGTERM handler (shut_down()) */
volatile int reread_pending = 0;	/* set by SIGHUP handler */
char version_string[] = SQUID_VERSION;
char appname[] = "squid";
char localhost[] = "127.0.0.1";
struct in_addr local_addr;
char *dash_str = "-";

/* for error reporting from xmalloc and friends */
extern void (*failure_notify) _PARAMS((char *));

static volatile int rotate_pending = 0;		/* set by SIGUSR1 handler */
static int httpPortNumOverride = 1;
static int icpPortNumOverride = 1;	/* Want to detect "-u 0" */
#if MALLOC_DBG
static int malloc_debug_level = 0;
#endif

static time_t next_cleaning;
static time_t next_maintain;
static time_t next_dirclean;
static time_t next_announce;
static time_t next_ip_purge;

static void rotate_logs _PARAMS((int));
static void reconfigure _PARAMS((int));
static void mainInitialize _PARAMS((void));
static void mainReinitialize _PARAMS((void));
static time_t mainMaintenance _PARAMS((void));
static void usage _PARAMS((void));
static void mainParseOptions _PARAMS((int, char **));
static void sendSignal _PARAMS((void));

static void
usage(void)
{
    fprintf(stderr, "\
Usage: %s [-hsvzCDFRUVY] [-f config-file] [-[au] port] [-k signal]\n\
       -a port   Specify ASCII port number (default: %d).\n\
       -f file   Use given config-file instead of\n\
                 %s\n\
       -h        Print help message.\n\
       -i        Disable IP caching.\n\
       -k reconfigure|rotate|shutdown|interrupt|kill|debug|check\n\
		 Send signal to running copy and exit.\n\
       -s        Enable logging to syslog.\n\
       -u port   Specify ICP port number (default: %d), disable with 0.\n\
       -v        Print version.\n\
       -z        Zap disk storage -- deletes all objects in disk cache.\n\
       -C        Do not catch fatal signals.\n\
       -D        Disable initial DNS tests.\n\
       -F        Foreground fast store rebuild.\n\
       -R        Do not set REUSEADDR on port.\n\
       -U        Unlink expired objects on reload.\n\
       -V        Virtual host httpd-accelerator.\n\
       -Y        Only return UDP_HIT or UDP_RELOADING during fast reload.\n",
	appname, CACHE_HTTP_PORT, DefaultConfigFile, CACHE_ICP_PORT);
    exit(1);
}

static void
mainParseOptions(int argc, char *argv[])
{
    extern char *optarg;
    int c;

    while ((c = getopt(argc, argv, "CDFRUVYa:bf:hik:m:su:vz?")) != -1) {
	switch (c) {
	case 'C':
	    opt_catch_signals = 0;
	    break;
	case 'D':
	    opt_dns_tests = 0;
	    break;
	case 'F':
	    opt_foreground_rebuild = 1;
	    break;
	case 'R':
	    do_reuse = 0;
	    break;
	case 'U':
	    opt_unlink_on_reload = 1;
	    break;
	case 'V':
	    vhost_mode = 1;
	    break;
	case 'Y':
	    opt_reload_hit_only = 1;
	    break;
	case 'a':
	    httpPortNumOverride = atoi(optarg);
	    break;
	case 'b':
	    unbuffered_logs = 0;
	    break;
	case 'f':
	    xfree(ConfigFile);
	    ConfigFile = xstrdup(optarg);
	    break;
	case 'h':
	    usage();
	    break;
	case 'i':
	    opt_no_ipcache = 1;
	    break;
	case 'k':
	    if (strlen(optarg) < 1)
		usage();
	    if (!strncmp(optarg, "reconfigure", strlen(optarg)))
		opt_send_signal = SIGHUP;
	    else if (!strncmp(optarg, "rotate", strlen(optarg)))
		opt_send_signal = SIGUSR1;
	    else if (!strncmp(optarg, "debug", strlen(optarg)))
		opt_send_signal = SIGUSR2;
	    else if (!strncmp(optarg, "shutdown", strlen(optarg)))
		opt_send_signal = SIGTERM;
	    else if (!strncmp(optarg, "interrupt", strlen(optarg)))
		opt_send_signal = SIGINT;
	    else if (!strncmp(optarg, "kill", strlen(optarg)))
		opt_send_signal = SIGKILL;
	    else if (!strncmp(optarg, "check", strlen(optarg)))
		opt_send_signal = 0;	/* SIGNULL */
	    else
		usage();
	    break;
	case 'm':
#if MALLOC_DBG
	    malloc_debug_level = atoi(optarg);
	    /* NOTREACHED */
	    break;
#else
	    fatal("Need to add -DMALLOC_DBG when compiling to use -m option");
#endif
	case 's':
	    opt_syslog_enable = 1;
	    break;
	case 'u':
	    icpPortNumOverride = atoi(optarg);
	    if (icpPortNumOverride < 0)
		icpPortNumOverride = 0;
	    break;
	case 'v':
	    printf("Squid Cache: Version %s\n", version_string);
	    exit(0);
	    /* NOTREACHED */
	case 'z':
	    opt_zap_disk_store = 1;
	    break;
	case '?':
	default:
	    usage();
	    break;
	}
    }
}

static void
rotate_logs(int sig)
{
    debug(21, 1, "rotate_logs: SIGUSR1 received.\n");
    rotate_pending = 1;
#if !HAVE_SIGACTION
    signal(sig, rotate_logs);
#endif
}

static void
reconfigure(int sig)
{
    debug(21, 1, "reconfigure: SIGHUP received\n");
    debug(21, 1, "Waiting %d seconds for active connections to finish\n",
	Config.lifetimeShutdown);
    reread_pending = 1;
#if !HAVE_SIGACTION
    signal(sig, reconfigure);
#endif
}

void
shut_down(int sig)
{
    shutdown_pending = sig == SIGINT ? -1 : 1;
    debug(21, 1, "Preparing for shutdown after %d connections\n",
	ntcpconn + nudpconn);
    debug(21, 1, "Waiting %d seconds for active connections to finish\n",
	shutdown_pending > 0 ? Config.lifetimeShutdown : 0);
#if SA_RESETHAND == 0
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
#endif
}

void
serverConnectionsOpen(void)
{
    struct in_addr addr;
    u_short port;
    /* Get our real priviliges */

    /* Open server ports */
    enter_suid();
    theHttpConnection = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_incoming,
	Config.Port.http,
	COMM_NONBLOCKING,
	"HTTP Port");
    leave_suid();
    if (theHttpConnection < 0) {
	fatal("Cannot open HTTP Port");
    }
    fd_note(theHttpConnection, "HTTP socket");
    comm_listen(theHttpConnection);
    comm_set_select_handler(theHttpConnection,
	COMM_SELECT_READ,
	asciiHandleConn,
	0);
    debug(1, 1, "Accepting HTTP connections on FD %d.\n",
	theHttpConnection);

    if (!httpd_accel_mode || Config.Accel.withProxy) {
	if ((port = Config.Port.icp) > (u_short) 0) {
	    enter_suid();
	    theInIcpConnection = comm_open(SOCK_DGRAM,
		0,
		Config.Addrs.udp_incoming,
		port,
		COMM_NONBLOCKING,
		"ICP Port");
	    leave_suid();
	    if (theInIcpConnection < 0)
		fatal("Cannot open ICP Port");
	    fd_note(theInIcpConnection, "ICP socket");
	    comm_set_select_handler(theInIcpConnection,
		COMM_SELECT_READ,
		icpHandleUdp,
		0);
	    debug(1, 1, "Accepting ICP connections on FD %d.\n",
		theInIcpConnection);

	    if ((addr = Config.Addrs.udp_outgoing).s_addr != INADDR_NONE) {
		enter_suid();
		theOutIcpConnection = comm_open(SOCK_DGRAM,
		    0,
		    addr,
		    port,
		    COMM_NONBLOCKING,
		    "ICP Port");
		leave_suid();
		if (theOutIcpConnection < 0)
		    fatal("Cannot open Outgoing ICP Port");
		comm_set_select_handler(theOutIcpConnection,
		    COMM_SELECT_READ,
		    icpHandleUdp,
		    0);
		debug(1, 1, "Accepting ICP connections on FD %d.\n",
		    theOutIcpConnection);
		fd_note(theOutIcpConnection, "Outgoing ICP socket");
		fd_note(theInIcpConnection, "Incoming ICP socket");
	    } else {
		theOutIcpConnection = theInIcpConnection;
	    }
	}
    }
#if USE_ICMP
    icmpOpen();
    netdbInit();
#endif
}

void
serverConnectionsClose(void)
{
    /* NOTE, this function will be called repeatedly while shutdown
     * is pending */
    if (theHttpConnection >= 0) {
	debug(21, 1, "FD %d Closing HTTP connection\n",
	    theHttpConnection);
	comm_close(theHttpConnection);
	comm_set_select_handler(theHttpConnection,
	    COMM_SELECT_READ,
	    NULL,
	    0);
	theHttpConnection = -1;
    }
    if (theInIcpConnection >= 0) {
	/* NOTE, don't close outgoing ICP connection, we need to write to
	 * it during shutdown */
	debug(21, 1, "FD %d Closing ICP connection\n",
	    theInIcpConnection);
	if (theInIcpConnection != theOutIcpConnection)
	    comm_close(theInIcpConnection);
	comm_set_select_handler(theInIcpConnection,
	    COMM_SELECT_READ,
	    NULL,
	    0);
	if (theInIcpConnection != theOutIcpConnection)
	    comm_set_select_handler(theOutIcpConnection,
		COMM_SELECT_READ,
		NULL,
		0);
	theInIcpConnection = -1;
    }
#if USE_ICMP
    icmpClose();
#endif
}

static void
mainReinitialize(void)
{
    debug(1, 0, "Restarting Squid Cache (version %s)...\n", version_string);
    /* Already called serverConnectionsClose and ipcacheShutdownServers() */
    neighborsDestroy();
    parseConfigFile(ConfigFile);
    _db_init(Config.Log.log, Config.debugOptions);
    neighbors_init();
    dnsOpenServers();
    redirectOpenServers();
    serverConnectionsOpen();
    (void) ftpInitialize();
    if (theOutIcpConnection >= 0 && (!httpd_accel_mode || Config.Accel.withProxy))
	neighbors_open(theOutIcpConnection);
    debug(1, 0, "Ready to serve requests.\n");
}

static void
mainInitialize(void)
{
    static int first_time = 1;
    if (opt_catch_signals) {
	squid_signal(SIGSEGV, death, SA_NODEFER | SA_RESETHAND);
	squid_signal(SIGBUS, death, SA_NODEFER | SA_RESETHAND);
    }
    squid_signal(SIGPIPE, SIG_IGN, SA_RESTART);
    squid_signal(SIGCHLD, sig_child, SA_NODEFER | SA_RESTART);

    if (ConfigFile == NULL)
	ConfigFile = xstrdup(DefaultConfigFile);
    parseConfigFile(ConfigFile);

    leave_suid();		/* Run as non privilegied user */

#if USE_ASYNC_IO
#if HAVE_AIO_INIT
    if (first_time)
	aio_init();
#endif
    squid_signal(SIGIO, aioSigHandler, SA_RESTART);
#endif

    if (httpPortNumOverride != 1)
	setHttpPortNum((u_short) httpPortNumOverride);
    if (icpPortNumOverride != 1)
	setIcpPortNum((u_short) icpPortNumOverride);

    _db_init(Config.Log.log, Config.debugOptions);
    fdstat_open(fileno(debug_log), FD_LOG);
    fd_note(fileno(debug_log), Config.Log.log);

    debug(1, 0, "Starting Squid Cache version %s for %s...\n",
	version_string,
	CONFIG_HOST_TYPE);
    debug(1, 1, "With %d file descriptors available\n", FD_SETSIZE);

    if (first_time) {
	stmemInit();		/* stmem must go before at least redirect */
	disk_init();		/* disk_init must go before ipcache_init() */
    }
    ipcache_init();
    fqdncache_init();
    dnsOpenServers();
    redirectOpenServers();
    neighbors_init();
    (void) ftpInitialize();

#if MALLOC_DBG
    malloc_debug(0, malloc_debug_level);
#endif

    if (first_time) {
	/* module initialization */
	urlInitialize();
	stat_init(&HTTPCacheInfo, Config.Log.access);
	stat_init(&ICPCacheInfo, NULL);
	storeInit();

	if (Config.effectiveUser) {
	    /* we were probably started as root, so cd to a swap
	     * directory in case we dump core */
	    if (chdir(swappath(0)) < 0) {
		debug(1, 0, "%s: %s\n", swappath(0), xstrerror());
		fatal_dump("Cannot cd to swap directory?");
	    }
	}
	/* after this point we want to see the mallinfo() output */
	do_mallinfo = 1;
    }
    serverConnectionsOpen();
    if (theOutIcpConnection >= 0 && (!httpd_accel_mode || Config.Accel.withProxy))
	neighbors_open(theOutIcpConnection);

    if (first_time)
	writePidFile();		/* write PID file */

    squid_signal(SIGUSR1, rotate_logs, SA_RESTART);
    squid_signal(SIGUSR2, sigusr2_handle, SA_RESTART);
    squid_signal(SIGHUP, reconfigure, SA_RESTART);
    squid_signal(SIGTERM, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);
    squid_signal(SIGINT, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);
    debug(1, 0, "Ready to serve requests.\n");

    if (first_time) {
	next_cleaning = squid_curtime + Config.cleanRate;
	next_maintain = squid_curtime + 0;
	next_dirclean = squid_curtime + 15;
	next_announce = squid_curtime + Config.Announce.rate;
	next_ip_purge = squid_curtime + 10;
    }
    first_time = 0;
}

static time_t
mainMaintenance(void)
{
    time_t next;
    if (squid_curtime >= next_maintain) {
	storeMaintainSwapSpace();
	next_maintain = squid_curtime + 1;
    }
    if (store_rebuilding == STORE_NOT_REBUILDING) {
	if (squid_curtime >= next_ip_purge) {
	    ipcache_purgelru();
	    next_ip_purge = squid_curtime + 10;
	} else if (squid_curtime >= next_dirclean) {
	    /* clean a cache directory every 15 seconds */
	    /* 15 * 16 * 256 = 17 hrs */
	    storeDirClean();
	    next_dirclean = squid_curtime + 15;
	} else if (squid_curtime >= next_cleaning) {
	    storePurgeOld();
	    next_cleaning = squid_curtime + Config.cleanRate;
	} else if (squid_curtime >= next_announce) {
	    send_announce();
	    next_announce = squid_curtime + Config.Announce.rate;
	}
    }
    next = next_ip_purge;
    if (next_dirclean < next)
	next = next_dirclean;
    if (next_cleaning < next)
	next = next_cleaning;
    if (next_announce < next)
	next = next_announce;
    return next - squid_curtime;
}

int
main(int argc, char **argv)
{
    int errcount = 0;
    int n;			/* # of GC'd objects */
    time_t loop_delay;

    /* call mallopt() before anything else */
#if HAVE_MALLOPT
#ifdef M_GRAIN
    /* Round up all sizes to a multiple of this */
    mallopt(M_GRAIN, 16);
#endif
#ifdef M_MXFAST
    /* biggest size that is considered a small block */
    mallopt(M_MXFAST, 256);
#endif
#ifdef M_NBLKS
    /* allocate this many small blocks at once */
    mallopt(M_NLBLKS, 32);
#endif
#endif /* HAVE_MALLOPT */

    memset(&local_addr, '\0', sizeof(struct in_addr));
    local_addr.s_addr = inet_addr(localhost);

    errorInitialize();

    squid_starttime = getCurrentTime();
    failure_notify = fatal_dump;

    mainParseOptions(argc, argv);

    /* send signal to running copy and exit */
    if (opt_send_signal != -1) {
	sendSignal();
	/* NOTREACHED */
    }
    setMaxFD();

    if (opt_catch_signals)
	for (n = FD_SETSIZE; n > 2; n--)
	    close(n);

    /*init comm module */
    comm_init();

    /* we have to init fdstat here. */
    fdstat_init(PREOPEN_FD);
    fdstat_open(0, FD_LOG);
    fdstat_open(1, FD_LOG);
    fdstat_open(2, FD_LOG);
    fd_note(0, "STDIN");
    fd_note(1, "STDOUT");
    fd_note(2, "STDERR");

    /* preinit for debug module */
    debug_log = stderr;
    hash_init(0);

    mainInitialize();

    /* main loop */
    for (;;) {
	if (rotate_pending) {
	    ftpServerClose();
	    _db_rotate_log();	/* cache.log */
	    storeWriteCleanLog();
	    storeRotateLog();	/* store.log */
	    stat_rotate_log();	/* access.log */
	    (void) ftpInitialize();
	    rotate_pending = 0;
	}
	if ((loop_delay = mainMaintenance()) < 0)
	    loop_delay = 0;
	else if (loop_delay > 10)
	    loop_delay = 10;
	if (doBackgroundProcessing())
	    loop_delay = 0;
	switch (comm_select(loop_delay)) {
	case COMM_OK:
	    errcount = 0;	/* reset if successful */
	    break;
	case COMM_ERROR:
	    errcount++;
	    debug(1, 0, "Select loop Error. Retry %d\n", errcount);
	    if (errcount == 10)
		fatal_dump("Select Loop failed!");
	    break;
	case COMM_SHUTDOWN:
	    /* delayed close so we can transmit while shutdown pending */
	    if (theOutIcpConnection > 0) {
		comm_close(theOutIcpConnection);
		theOutIcpConnection = -1;
	    }
	    if (shutdown_pending) {
		normal_shutdown();
		exit(0);
	    } else if (reread_pending) {
		mainReinitialize();
		reread_pending = 0;	/* reset */
	    } else {
		fatal_dump("MAIN: SHUTDOWN from comm_select, but nothing pending.");
	    }
	    break;
	case COMM_TIMEOUT:
	    break;
	default:
	    fatal_dump("MAIN: Internal error -- this should never happen.");
	    break;
	}
    }
    /* NOTREACHED */
    return 0;
}

static void
sendSignal(void)
{
    int pid;
    debug_log = stderr;
    if (ConfigFile == NULL)
	ConfigFile = xstrdup(DefaultConfigFile);
    parseConfigFile(ConfigFile);
    pid = readPidFile();
    if (pid > 1) {
	if (kill(pid, opt_send_signal) &&
	/* ignore permissions if just running check */
	    !(opt_send_signal == 0 && errno == EPERM)) {
	    fprintf(stderr, "%s: ERROR: Could not send ", appname);
	    fprintf(stderr, "signal %d to process %d: %s\n",
		opt_send_signal, pid, xstrerror());
	    exit(1);
	}
    } else {
	fprintf(stderr, "%s: ERROR: No running copy\n", appname);
	exit(1);
    }
    /* signal successfully sent */
    exit(0);
}
