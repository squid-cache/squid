/* $Id: main.cc,v 1.42 1996/04/17 17:45:13 wessels Exp $ */

/* DEBUG: Section 1             main: startup and main loop */

#include "squid.h"

time_t squid_starttime = 0;
time_t next_cleaning = 0;
int theAsciiConnection = -1;
int theUdpConnection = -1;
int do_reuse = 1;
int opt_unlink_on_reload = 0;
int catch_signals = 1;
int do_dns_test = 1;
int vhost_mode = 0;
int unbuffered_logs = 1;	/* debug and hierarhcy unbuffered by default */
int shutdown_pending = 0;	/* set by SIGTERM handler (shut_down()) */
int reread_pending = 0;		/* set by SIGHUP handler */
char *version_string = SQUID_VERSION;
char *appname = "squid";

extern void (*failure_notify) ();	/* for error reporting from xmalloc */

static int asciiPortNumOverride = 0;
static int udpPortNumOverride = 0;
static int malloc_debug_level = 0;

static void usage()
{
    fprintf(stderr, "\
Usage: %s [-Rsehvz] [-f config-file] [-[apu] port]\n\
       -h        Print help message.\n\
       -s        Enable logging to syslog.\n\
       -v        Print version.\n\
       -z        Zap disk storage -- deletes all objects in disk cache.\n\
       -C        Do not catch fatal signals.\n\
       -D        Disable initial DNS tests.\n\
       -R        Do not set REUSEADDR on port.\n\
       -U        Unlink expired objects on reload.\n\
       -f file   Use given config-file instead of\n\
                 %s\n\
       -a port	 Specify ASCII port number (default: %d).\n\
       -u port	 Specify UDP port number (default: %d).\n",
	appname, DEFAULT_CONFIG_FILE, CACHE_HTTP_PORT, CACHE_ICP_PORT);
    exit(1);
}

static void mainParseOptions(argc, argv)
     int argc;
     char *argv[];
{
    extern char *optarg;
    int c;

    while ((c = getopt(argc, argv, "vCDRVbsif:a:p:u:m:zh?")) != -1) {
	switch (c) {
	case 'v':
	    printf("Squid Cache: Version %s\n", version_string);
	    exit(0);
	    /* NOTREACHED */
	case 'b':
	    unbuffered_logs = 0;
	    break;
	case 'V':
	    vhost_mode = 1;
	    break;
	case 'C':
	    catch_signals = 0;
	    break;
	case 'D':
	    do_dns_test = 0;
	    break;
	case 's':
	    syslog_enable = 0;
	    break;
	    break;
	case 'R':
	    do_reuse = 0;
	    break;
	case 'U':
	    opt_unlink_on_reload = 1;
	    break;
	case 'f':
	    xfree(ConfigFile);
	    ConfigFile = xstrdup(optarg);
	    break;
	case 'a':
	    asciiPortNumOverride = atoi(optarg);
	    break;
	case 'u':
	    udpPortNumOverride = atoi(optarg);
	    break;
	case 'm':
	    malloc_debug_level = atoi(optarg);
	    break;
	case 'z':
	    zap_disk_store = 1;
	    break;
	case '?':
	case 'h':
	default:
	    usage();
	    break;
	}
    }
}

void serverConnectionsOpen()
{
    theAsciiConnection = comm_open(COMM_NONBLOCKING,
	getAsciiPortNum(),
	0,
	"Ascii Port");
    if (theAsciiConnection < 0) {
	fatal("Cannot open ascii Port");
    }
    fd_note(theAsciiConnection, "HTTP (Ascii) socket");
    comm_listen(theAsciiConnection);
    comm_set_select_handler(theAsciiConnection,
	COMM_SELECT_READ,
	asciiHandleConn,
	0);
    debug(1, 1, "Accepting HTTP (ASCII) connections on FD %d.\n",
	theAsciiConnection);

    if (!httpd_accel_mode || getAccelWithProxy()) {
	if (getUdpPortNum() > -1) {
	    theUdpConnection = comm_open(COMM_NONBLOCKING | COMM_DGRAM,
		getUdpPortNum(),
		0,
		"Ping Port");
	    if (theUdpConnection < 0)
		fatal("Cannot open UDP Port");
	    fd_note(theUdpConnection, "ICP (UDP) socket");
	    comm_set_select_handler(theUdpConnection,
		COMM_SELECT_READ,
		icpHandleUdp,
		0);
	    debug(1, 1, "Accepting ICP (UDP) connections on FD %d.\n",
		theUdpConnection);
	}
    }
}

void serverConnectionsClose()
{
    if (theAsciiConnection >= 0) {
	debug(21, 1, "FD %d Closing Ascii connection\n",
	    theAsciiConnection);
	comm_close(theAsciiConnection);
	comm_set_select_handler(theAsciiConnection,
	    COMM_SELECT_READ,
	    NULL,
	    0);
	theAsciiConnection = -1;
    }
    if (theUdpConnection >= 0) {
	debug(21, 1, "FD %d Closing Udp connection\n",
	    theUdpConnection);
	/* Dont actually close it, just disable the read handler */
	/* so we can still transmit while shutdown pending */
	/* comm_close(theUdpConnection); */
	comm_set_select_handler(theUdpConnection,
	    COMM_SELECT_READ,
	    NULL,
	    0);
	/* theUdpConnection = -1; */
    }
}

static void mainReinitialize()
{
    debug(1, 0, "Restarting Squid Cache (version %s)...\n", version_string);
    /* Already called serverConnectionsClose and ipcacheShutdownServers() */
    neighborsDestroy();

    parseConfigFile(ConfigFile);
    _db_init(getCacheLogFile());
    neighbors_init();
    ipcacheOpenServers();
    serverConnectionsOpen();
    if (theUdpConnection >= 0 && (!httpd_accel_mode || getAccelWithProxy()))
	neighbors_open(theUdpConnection);
    debug(1, 0, "Ready to serve requests.\n");
}

static void mainInitialize()
{
    static int first_time = 1;

    if (catch_signals) {
	signal(SIGSEGV, death);
	signal(SIGBUS, death);
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, sig_child);

    if (ConfigFile == NULL)
	ConfigFile = xstrdup(DefaultConfigFile);
    parseConfigFile(ConfigFile);

    if (asciiPortNumOverride > 0)
	setAsciiPortNum(asciiPortNumOverride);
    if (udpPortNumOverride > 0)
	setUdpPortNum(udpPortNumOverride);

    _db_init(getCacheLogFile());
    fdstat_open(fileno(debug_log), LOG);
    fd_note(fileno(debug_log), getCacheLogFile());

    debug(1, 0, "Starting Squid Cache (version %s)...\n", version_string);

    if (first_time) {
	disk_init();	/* disk_init must go before ipcache_init() */
    }

    ipcache_init();
    neighbors_init();
    ftpInitialize();

#if defined(MALLOC_DBG)
    malloc_debug(0, malloc_debug_level);
#endif

    /* do suid checking here */
    check_suid();

    if (first_time) {
	first_time = 0;
	/* module initialization */
	urlInitialize();
	stat_init(&CacheInfo, getAccessLogFile());
	storeInit();
	stmemInit();
	writePidFile();

	/* after this point we want to see the mallinfo() output */
	do_mallinfo = 1;
    }
    serverConnectionsOpen();
    if (theUdpConnection >= 0 && (!httpd_accel_mode || getAccelWithProxy()))
	neighbors_open(theUdpConnection);

    signal(SIGUSR1, rotate_logs);
    signal(SIGHUP, reconfigure);
    signal(SIGTERM, shut_down);
    signal(SIGINT, shut_down);

    debug(1, 0, "Ready to serve requests.\n");
}


int main(argc, argv)
     int argc;
     char **argv;
{
    int errcount = 0;
    int n;			/* # of GC'd objects */
    time_t last_maintain = 0;
    time_t last_announce = 0;
    time_t loop_delay;

    errorInitialize();

    squid_starttime = getCurrentTime();
    failure_notify = fatal_dump;

    mainParseOptions(argc, argv);

    setMaxFD();

    for (n = getMaxFD(); n > 2; n--)
	close(n);

#if HAVE_MALLOPT
    /* set malloc option */
    /* use small block algorithm for faster allocation */
    /* grain of small block */
    mallopt(M_GRAIN, 16);
    /* biggest size that is considered a small block */
    mallopt(M_MXFAST, 4096);
    /* number of holding small block */
    mallopt(M_NLBLKS, 100);
#endif

    /*init comm module */
    comm_init();

    /* we have to init fdstat here. */
    fdstat_init(PREOPEN_FD);
    fdstat_open(0, LOG);
    fdstat_open(1, LOG);
    fdstat_open(2, LOG);
    fd_note(0, "STDIN");
    fd_note(1, "STDOUT");
    fd_note(2, "STDERR");

    /* enable syslog by default */
    syslog_enable = 0;

    /* preinit for debug module */
    debug_log = stderr;
    hash_init(0);

    mainInitialize();

    /* main loop */
    if (getCleanRate() > 0)
	next_cleaning = time(0L) + getCleanRate();
    while (1) {
	loop_delay = (time_t) 60;
	/* maintain cache storage */
	if (squid_curtime > last_maintain) {
	    storeMaintainSwapSpace();
	    last_maintain = squid_curtime;
	}
	/* do background processing */
	if (doBackgroundProcessing())
	    loop_delay = (time_t) 0;
	switch (comm_select(loop_delay, next_cleaning)) {
	case COMM_OK:
	    /* do nothing */
	    break;
	case COMM_ERROR:
	    errcount++;
	    debug(1, 0, "Select loop Error. Retry. %d\n", errcount);
	    if (errcount == 10)
		fatal_dump("Select Loop failed!");
	    break;
	case COMM_TIMEOUT:
	    /* this happens after 1 minute of idle time, or
	     * when next_cleaning has arrived */
	    /* garbage collection */
	    if (getCleanRate() > 0 && squid_curtime >= next_cleaning) {
		debug(1, 1, "Performing a garbage collection...\n");
		n = storePurgeOld();
		debug(1, 1, "Garbage collection done, %d objects removed\n", n);
		next_cleaning = squid_curtime + getCleanRate();
	    }
	    if ((n = getAnnounceRate()) > 0) {
		if (squid_curtime > last_announce + n)
		    send_announce();
		last_announce = squid_curtime;
	    }
	    /* house keeping */
	    break;
	case COMM_SHUTDOWN:
	    /* delayed close so we can transmit while shutdown pending */
	    if (theUdpConnection > 0) {
		comm_close(theUdpConnection);
		theUdpConnection = -1;
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
	default:
	    fatal_dump("MAIN: Internal error -- this should never happen.");
	    break;
	}
    }
    /* NOTREACHED */
    exit(0);
}
