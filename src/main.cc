
/*
 * $Id: main.cc,v 1.203 1998/01/06 07:11:53 wessels Exp $
 *
 * DEBUG: section 1     Startup and Main Loop
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

/* for error reporting from xmalloc and friends */
extern void (*failure_notify) (const char *);

static int opt_send_signal = -1;
static int opt_no_daemon = 0;
static volatile int rotate_pending = 0;		/* set by SIGUSR1 handler */
static int httpPortNumOverride = 1;
static int icpPortNumOverride = 1;	/* Want to detect "-u 0" */
#if MALLOC_DBG
static int malloc_debug_level = 0;
#endif

static SIGHDLR rotate_logs;
static SIGHDLR reconfigure;
#if ALARM_UPDATES_TIME
static SIGHDLR time_tick;
#endif
static void mainInitialize(void);
static void mainReconfigure(void);
static void usage(void);
static void mainParseOptions(int, char **);
static void sendSignal(void);
static void serverConnectionsOpen(void);
static void watch_child(char **);
static void setEffectiveUser(void);

static void
usage(void)
{
    fprintf(stderr,
	"Usage: %s [-dhsvzCDFNRVYX] [-f config-file] [-[au] port] [-k signal]\n"
	"       -a port   Specify HTTP port number (default: %d).\n"
	"       -d        Write debugging to stderr also.\n"
	"       -f file   Use given config-file instead of\n"
	"                 %s\n"
	"       -h        Print help message.\n"
	"       -k reconfigure|rotate|shutdown|interrupt|kill|debug|check\n"
	"                 Send signal to running copy and exit.\n"
	"       -s        Enable logging to syslog.\n"
	"       -u port   Specify ICP port number (default: %d), disable with 0.\n"
	"       -v        Print version.\n"
	"       -z        Create swap directories\n"
	"       -C        Do not catch fatal signals.\n"
	"       -D        Disable initial DNS tests.\n"
	"       -F        Foreground fast store rebuild.\n"
	"       -N        No daemon mode.\n"
	"       -R        Do not set REUSEADDR on port.\n"
	"       -V        Virtual host httpd-accelerator.\n"
	"       -X        Force full debugging.\n"
	"       -Y        Only return UDP_HIT or UDP_MISS_NOFETCH during fast reload.\n",
	appname, CACHE_HTTP_PORT, DefaultConfigFile, CACHE_ICP_PORT);
    exit(1);
}

static void
mainParseOptions(int argc, char *argv[])
{
    extern char *optarg;
    int c;

    while ((c = getopt(argc, argv, "CDFNRVYXa:df:hk:m:su:vz?")) != -1) {
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
	case 'N':
	    opt_no_daemon = 1;
	    break;
	case 'R':
	    do_reuse = 0;
	    break;
	case 'V':
	    vhost_mode = 1;
	    break;
	case 'X':
	    /* force full debugging */
	    sigusr2_handle(SIGUSR2);
	    break;
	case 'Y':
	    opt_reload_hit_only = 1;
	    break;
	case 'a':
	    httpPortNumOverride = atoi(optarg);
	    break;
	case 'd':
	    opt_debug_stderr = 1;
	    break;
	case 'f':
	    xfree(ConfigFile);
	    ConfigFile = xstrdup(optarg);
	    break;
	case 'h':
	    usage();
	    break;
	case 'k':
	    if ((int) strlen(optarg) < 1)
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
	    /* NOTREACHED */
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
	    opt_create_swap_dirs = 1;
	    break;
	case '?':
	default:
	    usage();
	    break;
	}
    }
}

/* ARGSUSED */
static void
rotate_logs(int sig)
{
    debug(1, 1) ("rotate_logs: SIGUSR1 received.\n");
    rotate_pending = 1;
#if !HAVE_SIGACTION
    signal(sig, rotate_logs);
#endif
}

#if ALARM_UPDATES_TIME
static void
time_tick(int sig)
{
    getCurrentTime();
    alarm(1);
#if !HAVE_SIGACTION
    signal(sig, time_tick);
#endif
}

#endif

/* ARGSUSED */
static void
reconfigure(int sig)
{
    reconfigure_pending = 1;
#if !HAVE_SIGACTION
    signal(sig, reconfigure);
#endif
}

void
shut_down(int sig)
{
    shutdown_pending = sig == SIGINT ? -1 : 1;
    debug(1, 1) ("Preparing for shutdown after %d requests\n",
	Counter.client_http.requests);
    debug(1, 1) ("Waiting %d seconds for active connections to finish\n",
	shutdown_pending > 0 ? Config.shutdownLifetime : 0);
#ifdef KILL_PARENT_OPT
    {
	pid_t ppid = getppid();
	if (ppid > 1) {
	    debug(1, 1) ("Killing RunCache, pid %d\n", ppid);
	    kill(ppid, sig);
	}
    }
#endif
#if SA_RESETHAND == 0
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
#endif
}

static void
serverConnectionsOpen(void)
{
    clientHttpConnectionsOpen();
    icpConnectionsOpen();
#ifdef SQUID_SNMP
    snmpConnectionOpen();
#endif
    clientdbInit();
    icmpOpen();
    netdbInit();
    asnInit();
    peerSelectInit();
}

void
serverConnectionsClose(void)
{
    /*
     * NOTE, this function will be called repeatedly while shutdown
     * is pending
     */
    int i;
    for (i = 0; i < NHttpSockets; i++) {
	if (HttpSockets[i] >= 0) {
	    debug(1, 1) ("FD %d Closing HTTP connection\n", HttpSockets[i]);
	    comm_close(HttpSockets[i]);
	    HttpSockets[i] = -1;
	}
    }
    NHttpSockets = 0;
    if (theInIcpConnection > -1) {
	/*
	 * NOTE, don't close outgoing ICP connection, we need to write
	 * to it during shutdown.
	 */
	debug(1, 1) ("FD %d Closing ICP connection\n",
	    theInIcpConnection);
	if (theInIcpConnection != theOutIcpConnection) {
	    comm_close(theInIcpConnection);
	    assert(theOutIcpConnection > -1);
	    /*
	     * Normally we only write to the outgoing ICP socket, but
	     * we also have a read handler there to catch messages sent
	     * to that specific interface.  During shutdown, we must
	     * disable reading on the outgoing socket.
	     */
	    commSetSelect(theOutIcpConnection,
		COMM_SELECT_READ,
		NULL,
		NULL,
		0);
	} else {
	    commSetSelect(theInIcpConnection,
		COMM_SELECT_READ,
		NULL,
		NULL,
		0);
	}
	theInIcpConnection = -1;
    }
    if (icmp_sock > -1)
	icmpClose();
#ifdef SQUID_SNMP
    snmpConnectionClose();
#endif
}

static void
mainReconfigure(void)
{
    debug(1, 0) ("Restarting Squid Cache (version %s)...\n", version_string);
    /* Already called serverConnectionsClose and ipcacheShutdownServers() */
    serverConnectionsClose();
    if (theOutIcpConnection > 0) {
	comm_close(theOutIcpConnection);
	theOutIcpConnection = -1;
    }
    dnsShutdownServers();
    asnCleanup();
    redirectShutdownServers();
    storeDirCloseSwapLogs();
    errorFree();
    parseConfigFile(ConfigFile);
    _db_init(Config.Log.log, Config.debugOptions);
    asnAclInitialize(Config.aclList);	/* reload network->AS database */
    ipcache_restart();		/* clear stuck entries */
    fqdncache_restart();	/* sigh, fqdncache too */
    errorInitialize();		/* reload error pages */
    dnsOpenServers();
    redirectOpenServers();
    serverConnectionsOpen();
    if (theOutIcpConnection >= 0 && (!Config2.Accel.on || Config.onoff.accel_with_proxy))
	neighbors_open(theOutIcpConnection);
    storeDirOpenSwapLogs();
    debug(1, 0) ("Ready to serve requests.\n");
}

static void 
setEffectiveUser(void)
{
    leave_suid();		/* Run as non privilegied user */
    if (geteuid() == 0) {
	debug(0, 0) ("Squid is not safe to run as root!  If you must\n");
	debug(0, 0) ("start Squid as root, then you must configure\n");
	debug(0, 0) ("it to run as a non-priveledged user with the\n");
	debug(0, 0) ("'cache_effective_user' option in the config file.\n");
	fatal("Don't run Squid as root, set 'cache_effective_user'!");
    }
}

static void
mainInitialize(void)
{
    if (opt_catch_signals) {
	squid_signal(SIGSEGV, death, SA_NODEFER | SA_RESETHAND);
	squid_signal(SIGBUS, death, SA_NODEFER | SA_RESETHAND);
    }
    squid_signal(SIGPIPE, SIG_IGN, SA_RESTART);
    squid_signal(SIGCHLD, sig_child, SA_NODEFER | SA_RESTART);

    if (!configured_once)
	cbdataInit();
    if (ConfigFile == NULL)
	ConfigFile = xstrdup(DefaultConfigFile);
    parseConfigFile(ConfigFile);

    setEffectiveUser();
    assert(Config.Port.http);
    if (httpPortNumOverride != 1)
	Config.Port.http->i = (u_short) httpPortNumOverride;
    if (icpPortNumOverride != 1)
	Config.Port.icp = (u_short) icpPortNumOverride;

    _db_init(Config.Log.log, Config.debugOptions);
    fd_open(fileno(debug_log), FD_LOG, Config.Log.log);

    debug(1, 0) ("Starting Squid Cache version %s for %s...\n",
	version_string,
	CONFIG_HOST_TYPE);
    debug(1, 0) ("Process ID %d\n", (int) getpid());
    debug(1, 1) ("With %d file descriptors available\n", Squid_MaxFD);

    if (!configured_once) {
	stmemInit();		/* stmem must go before at least redirect */
	disk_init();		/* disk_init must go before ipcache_init() */
    }
    ipcache_init();
    fqdncache_init();
    dnsOpenServers();
    redirectOpenServers();
    useragentOpenLog();
    errorInitialize();
    accessLogInit();

#if MALLOC_DBG
    malloc_debug(0, malloc_debug_level);
#endif

    if (!configured_once) {
	unlinkdInit();
	/* module initialization */
	urlInitialize();
	stat_init(&HTTPCacheInfo, Config.Log.access);
	stat_init(&ICPCacheInfo, NULL);
	objcacheInit();
	storeInit();
	asnAclInitialize(Config.aclList);
	if (Config.effectiveUser) {
	    /* we were probably started as root, so cd to a swap
	     * directory in case we dump core */
	    if (chdir(storeSwapDir(0)) < 0) {
		debug(50, 0) ("%s: %s\n", storeSwapDir(0), xstrerror());
		fatal_dump("Cannot cd to swap directory?");
	    }
	}
	/* after this point we want to see the mallinfo() output */
	do_mallinfo = 1;
	mimeInit(Config.mimeTablePathname);
	pconnInit();
    }
    serverConnectionsOpen();
    if (theOutIcpConnection >= 0 && (!Config2.Accel.on || Config.onoff.accel_with_proxy))
	neighbors_open(theOutIcpConnection);

    if (!configured_once)
	writePidFile();		/* write PID file */

    squid_signal(SIGUSR1, rotate_logs, SA_RESTART);
    squid_signal(SIGUSR2, sigusr2_handle, SA_RESTART);
    squid_signal(SIGHUP, reconfigure, SA_RESTART);
    squid_signal(SIGTERM, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);
    squid_signal(SIGINT, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);
#if ALARM_UPDATES_TIME
    squid_signal(SIGALRM, time_tick, SA_RESTART);
    alarm(1);
#endif
    debug(1, 0) ("Ready to serve requests.\n");

    if (!configured_once) {
	eventAdd("storeMaintain", storeMaintainSwapSpace, NULL, 1);
	eventAdd("storeDirClean", storeDirClean, NULL, 15);
	if (Config.onoff.announce)
	    eventAdd("start_announce", start_announce, NULL, 3600);
	eventAdd("ipcache_purgelru", ipcache_purgelru, NULL, 10);
	statAvgInit();
    }
    configured_once = 1;
#ifdef SQUID_SNMP
    snmpInit();
#endif
}

int
main(int argc, char **argv)
{
    int errcount = 0;
    int n;			/* # of GC'd objects */
    time_t loop_delay;

    debug_log = stderr;
    if (FD_SETSIZE < Squid_MaxFD)
	Squid_MaxFD = FD_SETSIZE;

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
    safe_inet_addr(localhost, &local_addr);
    memset(&any_addr, '\0', sizeof(struct in_addr));
    safe_inet_addr("0.0.0.0", &any_addr);
    memset(&no_addr, '\0', sizeof(struct in_addr));
    safe_inet_addr("255.255.255.255", &no_addr);
    squid_srandom(time(NULL));

    getCurrentTime();
    squid_start = current_time;
    failure_notify = fatal_dump;

    mainParseOptions(argc, argv);

    /* send signal to running copy and exit */
    if (opt_send_signal != -1) {
	sendSignal();
	/* NOTREACHED */
    }
    if (opt_create_swap_dirs) {
        if (ConfigFile == NULL)
            ConfigFile = xstrdup(DefaultConfigFile);
        cbdataInit();
        parseConfigFile(ConfigFile);
        setEffectiveUser();
        debug(0, 0)("Creating Swap Directories\n");
        storeCreateSwapDirectories();
        return 0;
    }   
    if (!opt_no_daemon)
	watch_child(argv);
    setMaxFD();

    if (opt_catch_signals)
	for (n = Squid_MaxFD; n > 2; n--)
	    close(n);

    /*init comm module */
    comm_init();

    /* we have to init fdstat here. */
    fdstat_init();
    fd_open(0, FD_LOG, "stdin");
    fd_open(1, FD_LOG, "stdout");
    fd_open(2, FD_LOG, "stderr");

    mainInitialize();

    /* main loop */
    for (;;) {
	if (reconfigure_pending) {
	    mainReconfigure();
	    reconfigure_pending = 0;	/* reset */
	} else if (rotate_pending) {
	    icmpClose();
	    _db_rotate_log();	/* cache.log */
	    storeWriteCleanLogs(1);
	    storeRotateLog();	/* store.log */
	    accessLogRotate();	/* access.log */
	    useragentRotateLog();	/* useragent.log */
	    icmpOpen();
	    rotate_pending = 0;
	}
	eventRun();
	if ((loop_delay = eventNextTime()) < 0)
	    loop_delay = 0;
#if HAVE_POLL
	switch (comm_poll(loop_delay)) {
#else
	switch (comm_select(loop_delay)) {
#endif
	case COMM_OK:
	    errcount = 0;	/* reset if successful */
	    break;
	case COMM_ERROR:
	    errcount++;
	    debug(1, 0) ("Select loop Error. Retry %d\n", errcount);
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
#if 0
	    } else if (reconfigure_pending) {
		mainReconfigure();
		reconfigure_pending = 0;	/* reset */
#endif
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
    pid_t pid;
    debug_log = stderr;
    if (ConfigFile == NULL)
	ConfigFile = xstrdup(DefaultConfigFile);
    cbdataInit();
    parseConfigFile(ConfigFile);
    pid = readPidFile();
    if (pid > 1) {
	if (kill(pid, opt_send_signal) &&
	/* ignore permissions if just running check */
	    !(opt_send_signal == 0 && errno == EPERM)) {
	    fprintf(stderr, "%s: ERROR: Could not send ", appname);
	    fprintf(stderr, "signal %d to process %d: %s\n",
		opt_send_signal, (int) pid, xstrerror());
	    exit(1);
	}
    } else {
	fprintf(stderr, "%s: ERROR: No running copy\n", appname);
	exit(1);
    }
    /* signal successfully sent */
    exit(0);
}

static void
watch_child(char *argv[])
{
    char *prog;
    int failcount = 0;
    time_t start;
    time_t stop;
#ifdef _SQUID_NEXT_
    union wait status;
#else
    int status;
#endif
    pid_t pid;
    if (*(argv[0]) == '(')
	return;
    for (;;) {
	if (fork() == 0) {
	    /* child */
	    prog = xstrdup(argv[0]);
	    argv[0] = xstrdup("(squid)");
	    execvp(prog, argv);
	    fatal("execvp failed");
	}
	/* parent */
	time(&start);
	do {
	    squid_signal(SIGINT, SIG_IGN, SA_RESTART);
#ifdef _SQUID_NEXT_
	    pid = wait3(&status, 0, NULL);
#else
	    pid = waitpid(-1, &status, 0);
#endif
	} while (pid > 0);
	time(&stop);
	if (stop - start < 10)
	    failcount++;
	else
	    failcount = 0;
	if (failcount == 5)
	    exit(1);
	if (WIFEXITED(status))
	    if (WEXITSTATUS(status) == 0)
		exit(0);
	squid_signal(SIGINT, SIG_DFL, SA_RESTART);
	sleep(3);
    }
    /* NOTREACHED */
}
