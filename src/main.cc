/* $Id: main.cc,v 1.19 1996/04/04 22:01:54 wessels Exp $ */

/* DEBUG: Section 1             main: startup and main loop */

#include "squid.h"

time_t cached_starttime = 0;
time_t next_cleaning = 0;
int theAsciiConnection = -1;
int theUdpConnection = -1;
int do_reuse = 1;
int catch_signals = 1;
int do_dns_test = 1;
char *config_file = NULL;
int vhost_mode = 0;
int unbuffered_logs = 1;	/* debug and hierarhcy unbuffered by default */

extern void (*failure_notify) ();	/* for error reporting from xmalloc */

static int asciiPortNumOverride = 0;
static int udpPortNumOverride = 0;


static void usage()
{
    fprintf(stderr, "\
Usage: cached [-Rsehvz] [-f config-file] [-[apu] port]\n\
       -h        Print help message.\n\
       -s        Enable logging to syslog.\n\
       -v        Print version.\n\
       -z        Zap disk storage -- deletes all objects in disk cache.\n\
       -C        Do not catch fatal signals.\n\
       -D        Disable initial DNS tests.\n\
       -R        Do not set REUSEADDR on port.\n\
       -f file   Use given config-file instead of\n\
                 $HARVEST_HOME/lib/cached.conf.\n\
       -a port	 Specify ASCII port number (default: %d).\n\
       -u port	 Specify UDP port number (default: %d).\n",
	CACHE_HTTP_PORT, CACHE_ICP_PORT);
    exit(1);
}

int main(argc, argv)
     int argc;
     char **argv;
{
    int c;
    int malloc_debug_level = 0;
    extern char *optarg;
    int errcount = 0;
    static int neighbors = 0;
    char *s = NULL;
    int n;			/* # of GC'd objects */
    time_t last_maintain = 0;

    cached_starttime = getCurrentTime();
    failure_notify = fatal_dump;

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

    if ((s = getenv("HARVEST_HOME")) != NULL) {
	config_file = (char *) xcalloc(1, strlen(s) + 64);
	sprintf(config_file, "%s/lib/cached.conf", s);
    } else {
	config_file = xstrdup("/usr/local/harvest/lib/cached.conf");
    }

    /* enable syslog by default */
    syslog_enable = 0;
    /* preinit for debug module */
    debug_log = stderr;
    hash_init(0);

    while ((c = getopt(argc, argv, "vCDRVbsif:a:p:u:m:zh?")) != -1)
	switch (c) {
	case 'v':
	    printf("Harvest Cache: Version %s\n", SQUID_VERSION);
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
	case 'f':
	    xfree(config_file);
	    config_file = xstrdup(optarg);
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

    if (catch_signals) {
	signal(SIGSEGV, death);
	signal(SIGBUS, death);
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, sig_child);
    signal(SIGHUP, rotate_logs);
    signal(SIGTERM, shut_down);
    signal(SIGINT, shut_down);

    parseConfigFile(config_file);

    if (!neighbors) {
	neighbors_create();
	++neighbors;
    };

    if (asciiPortNumOverride > 0)
	setAsciiPortNum(asciiPortNumOverride);
    if (udpPortNumOverride > 0)
	setUdpPortNum(udpPortNumOverride);

    _db_init(getCacheLogFile());
    fdstat_open(fileno(debug_log), LOG);
    fd_note(fileno(debug_log), getCacheLogFile());

    debug(1, 0, "Starting Harvest Cache (version %s)...\n", SQUID_VERSION);

    /* init ipcache */
    ipcache_init();

    /* init neighbors */
    neighbors_init();

    ftpInitialize();


#if defined(MALLOC_DBG)
    malloc_debug(0, malloc_debug_level);
#endif

    theAsciiConnection = comm_open(COMM_NONBLOCKING,
	getAsciiPortNum(),
	0,
	"Ascii Port");
    if (theAsciiConnection < 0) {
	fatal("Cannot open ascii Port");
    }
    fdstat_open(theAsciiConnection, Socket);
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
	    fdstat_open(theUdpConnection, Socket);
	    fd_note(theUdpConnection, "ICP (UDP) socket");
	    comm_set_select_handler(theUdpConnection,
		COMM_SELECT_READ,
		icpHandleUdp,
		0);
	    debug(1, 1, "Accepting ICP (UDP) connections on FD %d.\n",
		theUdpConnection);
	}
    }
    if (theUdpConnection > 0) {
	/* Now that the fd's are open, initialize neighbor connections */
	if (!httpd_accel_mode || getAccelWithProxy()) {
	    neighbors_open(theUdpConnection);
	}
    }
    /* do suid checking here */
    check_suid();

    /* module initialization */
    disk_init();
    stat_init(&CacheInfo, getAccessLogFile());
    storeInit();
    stmemInit();
    writePidFile();

    /* after this point we want to see the mallinfo() output */
    do_mallinfo = 1;
    debug(1, 0, "Ready to serve requests.\n");

    /* main loop */
    if (getCleanRate() > 0)
	next_cleaning = time(0L) + getCleanRate();
    while (1) {
	/* maintain cache storage */
	if (cached_curtime > last_maintain) {
	    storeMaintainSwapSpace();
	    last_maintain = cached_curtime;
	}
	switch (comm_select((long) 60, (long) 0, next_cleaning)) {
	case COMM_OK:
	    /* do nothing */
	    break;
	case COMM_ERROR:
	    errcount++;
	    debug(1, 0, "Select loop Error. Retry. %d\n", errcount);
	    if (errcount == 10)
		fatal_dump("Select Loop failed.!");
	    break;
	case COMM_TIMEOUT:
	    /* this happens after 1 minute of idle time, or
	     * when next_cleaning has arrived */
	    /* garbage collection */
	    if (getCleanRate() > 0 && cached_curtime >= next_cleaning) {
		debug(1, 1, "Performing a garbage collection...\n");
		n = storePurgeOld();
		debug(1, 1, "Garbage collection done, %d objects removed\n", n);
		next_cleaning = cached_curtime + getCleanRate();
	    }
	    /* house keeping */
	    break;
	default:
	    fatal_dump("MAIN: Internal error -- this should never happen.");
	    break;
	}
    }
    /* NOTREACHED */
    exit(0);
}
