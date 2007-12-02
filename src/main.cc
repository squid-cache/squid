
/*
 * $Id: main.cc,v 1.451 2007/12/02 08:23:56 amosjeffries Exp $
 *
 * DEBUG: section 1     Startup and Main Loop
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
#include "AccessLogEntry.h"
#include "authenticate.h"
#include "CacheManager.h"
#include "ConfigParser.h"
#include "errorpage.h"
#include "event.h"
#include "EventLoop.h"
#include "ExternalACL.h"
#include "Store.h"
#include "ICP.h"
#include "HttpReply.h"
#include "pconn.h"
#include "Mem.h"
#include "ACLASN.h"
#include "ACL.h"
#include "htcp.h"
#include "StoreFileSystem.h"
#include "DiskIO/DiskIOModule.h"
#include "comm.h"
#if USE_EPOLL
#include "comm_epoll.h"
#endif
#if USE_KQUEUE
#include "comm_kqueue.h"
#endif
#if USE_POLL
#include "comm_poll.h"
#endif
#if USE_SELECT
#include "comm_select.h"
#endif
#if USE_SELECT_WIN32
#include "comm_select.h"
#endif
#include "SquidTime.h"
#include "SwapDir.h"
#include "forward.h"
#include "MemPool.h"

#if USE_WIN32_SERVICE

#include "squid_windows.h"
#include <process.h>

static int opt_install_service = FALSE;
static int opt_remove_service = FALSE;
static int opt_signal_service = FALSE;
static int opt_command_line = FALSE;
extern void WIN32_svcstatusupdate(DWORD, DWORD);
void WINAPI WIN32_svcHandler(DWORD);

#endif

/* for error reporting from xmalloc and friends */
SQUIDCEXTERN void (*failure_notify) (const char *);

static int opt_parse_cfg_only = 0;
static char *opt_syslog_facility = NULL;
static int icpPortNumOverride = 1;	/* Want to detect "-u 0" */
static int configured_once = 0;
#if MALLOC_DBG
static int malloc_debug_level = 0;
#endif
static volatile int do_reconfigure = 0;
static volatile int do_rotate = 0;
static volatile int do_shutdown = 0;
static volatile int shutdown_status = 0;

static void mainRotate(void);
static void mainReconfigure(void);
static void mainInitialize(void);
static void usage(void);
static void mainParseOptions(int, char **);
static void sendSignal(void);
static void serverConnectionsOpen(void);
static void watch_child(char **);
static void setEffectiveUser(void);
#if MEM_GEN_TRACE
extern void log_trace_done();
extern void log_trace_init(char *);
#endif
static void SquidShutdown(void);
static void mainSetCwd(void);
static int checkRunningPid(void);

static CacheManager manager;

#ifndef _SQUID_MSWIN_
static const char *squid_start_script = "squid_start";
#endif

#if TEST_ACCESS
#include "test_access.c"
#endif

/* temporary thunk across to the unrefactored store interface */

class StoreRootEngine : public AsyncEngine
{

public:
    int checkEvents(int timeout)
    {
        Store::Root().callback();
        return EVENT_IDLE;
    };
};

class SignalDispatcher : public CompletionDispatcher
{

public:
    SignalDispatcher(EventLoop &loop) : loop(loop), events_dispatched(false) {}

    void addEventLoop(EventLoop * loop);
    virtual bool dispatch();

private:
    static void StopEventLoop(void * data)
    {
        static_cast<SignalDispatcher *>(data)->loop.stop();
    }

    EventLoop &loop;
    bool events_dispatched;
};

bool
SignalDispatcher::dispatch()
{
    PROF_start(SignalDispatcher_dispatch);

    if (do_reconfigure) {
        mainReconfigure();
        do_reconfigure = 0;
    } else if (do_rotate) {
        mainRotate();
        do_rotate = 0;
    } else if (do_shutdown) {
        time_t wait = do_shutdown > 0 ? (int) Config.shutdownLifetime : 0;
        debugs(1, 1, "Preparing for shutdown after " << statCounter.client_http.requests << " requests");
        debugs(1, 1, "Waiting " << wait << " seconds for active connections to finish");
        do_shutdown = 0;
        shutting_down = 1;
#if USE_WIN32_SERVICE

        WIN32_svcstatusupdate(SERVICE_STOP_PENDING, (wait + 1) * 1000);
#endif

        serverConnectionsClose();
        eventAdd("SquidShutdown", StopEventLoop, this, (double) (wait + 1), 1, false);
    }

    bool result = events_dispatched;
    events_dispatched = false;
    PROF_stop(SignalDispatcher_dispatch);
    return result;
}

static void
usage(void)
{
    fprintf(stderr,
#if USE_WIN32_SERVICE
            "Usage: %s [-cdhirvzCDFNRVYX] [-s | -l facility] [-f config-file] [-[au] port] [-k signal] [-n name] [-O CommandLine]\n"
#else
            "Usage: %s [-cdhvzCDFNRVYX] [-s | -l facility] [-f config-file] [-[au] port] [-k signal]\n"
#endif
            "       -a port   Specify HTTP port number (default: %d).\n"
            "       -d level  Write debugging to stderr also.\n"
            "       -f file   Use given config-file instead of\n"
            "                 %s\n"
            "       -h        Print help message.\n"
#if USE_WIN32_SERVICE
            "       -i        Installs as a Windows Service (see -n option).\n"
#endif
            "       -k reconfigure|rotate|shutdown|interrupt|kill|debug|check|parse\n"
            "                 Parse configuration file, then send signal to \n"
            "                 running copy (except -k parse) and exit.\n"
#if USE_WIN32_SERVICE
            "       -n name   Specify Windows Service name to use for service operations\n"
            "                 default is: " _WIN_SQUID_DEFAULT_SERVICE_NAME ".\n"
            "       -r        Removes a Windows Service (see -n option).\n"
#endif
            "       -s | -l facility\n"
            "                 Enable logging to syslog.\n"
            "       -u port   Specify ICP port number (default: %d), disable with 0.\n"
            "       -v        Print version.\n"
            "       -z        Create swap directories\n"
            "       -C        Do not catch fatal signals.\n"
            "       -D        Disable initial DNS tests.\n"
            "       -F        Don't serve any requests until store is rebuilt.\n"
            "       -N        No daemon mode.\n"
#if USE_WIN32_SERVICE
            "       -O options\n"
            "                 Set Windows Service Command line options in Registry.\n"
#endif
            "       -R        Do not set REUSEADDR on port.\n"
            "       -S        Double-check swap during rebuild.\n"
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

#if USE_WIN32_SERVICE

    while ((c = getopt(argc, argv, "CDFNO:RSVYXa:d:f:hik:m::n:rsl:u:vz?")) != -1)
#else

    while ((c = getopt(argc, argv, "CDFNRSYXa:d:f:hk:m::sl:u:vz?")) != -1)
#endif

    {

        switch (c)
        {

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
#if USE_WIN32_SERVICE

        case 'O':
            opt_command_line = 1;
            WIN32_Command_Line = xstrdup(optarg);
            break;
#endif

        case 'R':
            opt_reuseaddr = 0;
            break;

        case 'S':
            opt_store_doublecheck = 1;
            break;

        case 'X':
            /* force full debugging */
            Debug::parseOptions("debug_options ALL,9");
            Config.onoff.debug_override_X = 1;
            sigusr2_handle(SIGUSR2);
            break;

        case 'Y':
            opt_reload_hit_only = 1;

            break;

#if USE_WIN32_SERVICE

        case 'i':
            opt_install_service = TRUE;

            break;

#endif

        case 'a':
            add_http_port(optarg);

            break;

        case 'd':
            opt_debug_stderr = atoi(optarg);

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
#ifdef _SQUID_LINUX_THREADS_

                opt_send_signal = SIGQUIT;

#else

                opt_send_signal = SIGUSR1;

#endif

            else if (!strncmp(optarg, "debug", strlen(optarg)))
#ifdef _SQUID_LINUX_THREADS_

                opt_send_signal = SIGTRAP;

#else

                opt_send_signal = SIGUSR2;

#endif

            else if (!strncmp(optarg, "shutdown", strlen(optarg)))
                opt_send_signal = SIGTERM;
            else if (!strncmp(optarg, "interrupt", strlen(optarg)))
                opt_send_signal = SIGINT;
            else if (!strncmp(optarg, "kill", strlen(optarg)))
                opt_send_signal = SIGKILL;

#ifdef SIGTTIN

            else if (!strncmp(optarg, "restart", strlen(optarg)))
                opt_send_signal = SIGTTIN;      /* exit and restart by parent */

#endif

            else if (!strncmp(optarg, "check", strlen(optarg)))
                opt_send_signal = 0;	/* SIGNULL */
            else if (!strncmp(optarg, "parse", strlen(optarg)))
                opt_parse_cfg_only = 1;		/* parse cfg file only */
            else
                usage();

            break;

        case 'm':
            if (optarg) {
#if MALLOC_DBG
                malloc_debug_level = atoi(optarg);
#else

                fatal("Need to add -DMALLOC_DBG when compiling to use -mX option");
#endif

            } else {
#if XMALLOC_TRACE
                xmalloc_trace = !xmalloc_trace;
#else

                fatal("Need to configure --enable-xmalloc-debug-trace to use -m option");
#endif

            }

            break;
            /* NOTREACHED */

#if USE_WIN32_SERVICE

        case 'n':
            xfree(WIN32_Service_name);

            WIN32_Service_name = xstrdup(optarg);

            opt_signal_service = TRUE;

            break;

        case 'r':
            opt_remove_service = TRUE;

            break;

#endif

        case 'l':
            opt_syslog_facility = xstrdup(optarg);

        case 's':
#if HAVE_SYSLOG

            _db_set_syslog(opt_syslog_facility);

            break;

#else

            fatal("Logging to syslog not available on this platform");

            /* NOTREACHED */
#endif

        case 'u':
            icpPortNumOverride = atoi(optarg);

            if (icpPortNumOverride < 0)
                icpPortNumOverride = 0;

            break;

        case 'v':
            printf("Squid Cache: Version %s\nconfigure options: %s\n", version_string, SQUID_CONFIGURE_OPTIONS);

#if USE_WIN32_SERVICE

            printf("Compiled as Windows System Service.\n");

#endif

            exit(0);

            /* NOTREACHED */

        case 'z':
            opt_debug_stderr = 1;

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
void
rotate_logs(int sig)
{
    do_rotate = 1;
#ifndef _SQUID_MSWIN_
#if !HAVE_SIGACTION

    signal(sig, rotate_logs);
#endif
#endif
}

/* ARGSUSED */
void
reconfigure(int sig)
{
    do_reconfigure = 1;
#ifndef _SQUID_MSWIN_
#if !HAVE_SIGACTION

    signal(sig, reconfigure);
#endif
#endif
}

void
shut_down(int sig)
{
    do_shutdown = sig == SIGINT ? -1 : 1;
#ifdef SIGTTIN

    if (SIGTTIN == sig)
        shutdown_status = 1;

#endif
#ifndef _SQUID_MSWIN_
#ifdef KILL_PARENT_OPT

    if (getppid() > 1) {
        debugs(1, 1, "Killing RunCache, pid " << getppid());

        if (kill(getppid(), sig) < 0)
            debugs(1, 1, "kill " << getppid() << ": " << xstrerror());
    }

#endif
#if SA_RESETHAND == 0
    signal(SIGTERM, SIG_DFL);

    signal(SIGINT, SIG_DFL);

#endif
#endif
}

static void
serverConnectionsOpen(void)
{
    clientOpenListenSockets();
    icpConnectionsOpen();
#if USE_HTCP

    htcpInit();
#endif
#ifdef SQUID_SNMP

    snmpConnectionOpen();
#endif
#if USE_WCCP

    wccpConnectionOpen();
#endif

#if USE_WCCPv2

    wccp2ConnectionOpen();
#endif

    clientdbInit();
    icmpOpen();
    netdbInit();
    asnInit();
    ACL::Initialize();
    peerSelectInit();
#if USE_CARP

    carpInit();
#endif
}

void
serverConnectionsClose(void)
{
    assert(shutting_down || reconfiguring);
    clientHttpConnectionsClose();
    icpConnectionShutdown();
#if USE_HTCP

    htcpSocketShutdown();
#endif

    icmpClose();
#ifdef SQUID_SNMP

    snmpConnectionShutdown();
#endif
#if USE_WCCP

    wccpConnectionClose();
#endif
#if USE_WCCPv2

    wccp2ConnectionClose();
#endif

    asnFreeMemory();
}

static void
mainReconfigure(void)
{
    debugs(1, 1, "Reconfiguring Squid Cache (version " << version_string << ")...");
    reconfiguring = 1;
    /* Already called serverConnectionsClose and ipcacheShutdownServers() */
    serverConnectionsClose();
    icpConnectionClose();
#if USE_HTCP

    htcpSocketClose();
#endif
#ifdef SQUID_SNMP

    snmpConnectionClose();
#endif
#if USE_DNSSERVERS

    dnsShutdown();
#else

    idnsShutdown();
#endif

    redirectShutdown();
    authenticateShutdown();
    externalAclShutdown();
    storeDirCloseSwapLogs();
    storeLogClose();
    accessLogClose();
    useragentLogClose();
    refererCloseLog();
    errorClean();
    enter_suid();		/* root to read config file */
    parseConfigFile(ConfigFile, manager);
    setEffectiveUser();
    _db_init(Config.Log.log, Config.debugOptions);
    ipcache_restart();		/* clear stuck entries */
    authenticateUserCacheRestart();	/* clear stuck ACL entries */
    fqdncache_restart();	/* sigh, fqdncache too */
    parseEtcHosts();
    errorInitialize();		/* reload error pages */
    accessLogInit();
    storeLogOpen();
    useragentOpenLog();
    refererOpenLog();
#if USE_DNSSERVERS

    dnsInit();
#else

    idnsInit();
#endif

    redirectInit();
    authenticateInit(&Config.authConfiguration);
    externalAclInit();
#if USE_WCCP

    wccpInit();
#endif
#if USE_WCCPv2

    wccp2Init();
#endif

    serverConnectionsOpen();

    neighbors_init();
    neighborsRegisterWithCacheManager(manager);

    storeDirOpenSwapLogs();

    mimeInit(Config.mimeTablePathname);

    if (Config.onoff.announce) {
        if (!eventFind(start_announce, NULL))
            eventAdd("start_announce", start_announce, NULL, 3600.0, 1);
    } else {
        if (eventFind(start_announce, NULL))
            eventDelete(start_announce, NULL);
    }

    writePidFile();		/* write PID file */

    debugs(1, 1, "Ready to serve requests.");

    reconfiguring = 0;
}

static void
mainRotate(void)
{
    icmpClose();
#if USE_DNSSERVERS

    dnsShutdown();
#endif

    redirectShutdown();
    authenticateShutdown();
    externalAclShutdown();
    _db_rotate_log();		/* cache.log */
    storeDirWriteCleanLogs(1);
    storeLogRotate();		/* store.log */
    accessLogRotate();		/* access.log */
    useragentRotateLog();	/* useragent.log */
    refererRotateLog();		/* referer.log */
#if WIP_FWD_LOG

    fwdLogRotate();
#endif

    icmpOpen();
#if USE_DNSSERVERS

    dnsInit();
#endif

    redirectInit();
    authenticateInit(&Config.authConfiguration);
    externalAclInit();
}

static void
setEffectiveUser(void)
{
    keepCapabilities();
    leave_suid();		/* Run as non privilegied user */
#ifdef _SQUID_OS2_

    return;
#endif

    if (geteuid() == 0) {
        debugs(0, 0, "Squid is not safe to run as root!  If you must");
        debugs(0, 0, "start Squid as root, then you must configure");
        debugs(0, 0, "it to run as a non-priveledged user with the");
        debugs(0, 0, "'cache_effective_user' option in the config file.");
        fatal("Don't run Squid as root, set 'cache_effective_user'!");
    }
}

static void
mainSetCwd(void)
{
    char pathbuf[MAXPATHLEN];

    if (Config.coredump_dir) {
        if (0 == strcmp("none", Config.coredump_dir)) {
            (void) 0;
        } else if (chdir(Config.coredump_dir) == 0) {
            debugs(0, 1, "Set Current Directory to " << Config.coredump_dir);
            return;
        } else {
            debugs(50, 0, "chdir: " << Config.coredump_dir << ": " << xstrerror());
        }
    }

    /* If we don't have coredump_dir or couldn't cd there, report current dir */
    if (getcwd(pathbuf, MAXPATHLEN)) {
        debugs(0, 1, "Current Directory is " << pathbuf);
    } else {
        debugs(50, 0, "WARNING: Can't find current directory, getcwd: " << xstrerror());
    }
}

#if DELAY_POOLS
#include "DelayPools.h"
#endif

static void
mainInitialize(void)
{
    /* chroot if configured to run inside chroot */

    if (Config.chroot_dir && (chroot(Config.chroot_dir) != 0 || chdir("/") != 0)) {
        fatal("failed to chroot");
    }

    if (opt_catch_signals) {
        squid_signal(SIGSEGV, death, SA_NODEFER | SA_RESETHAND);
        squid_signal(SIGBUS, death, SA_NODEFER | SA_RESETHAND);
    }

    squid_signal(SIGPIPE, SIG_IGN, SA_RESTART);
    squid_signal(SIGCHLD, sig_child, SA_NODEFER | SA_RESTART);

    setEffectiveUser();

    if (icpPortNumOverride != 1)
        Config.Port.icp = (u_short) icpPortNumOverride;

    _db_init(Config.Log.log, Config.debugOptions);

    fd_open(fileno(debug_log), FD_LOG, Config.Log.log);

#if MEM_GEN_TRACE

    log_trace_init("/tmp/squid.alloc");

#endif

    debugs(1, 0, "Starting Squid Cache version " << version_string << " for " << CONFIG_HOST_TYPE << "...");

#ifdef _SQUID_WIN32_

    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        debugs(1, 0, "Running as " << WIN32_Service_name << " Windows System Service on " << WIN32_OS_string);
        debugs(1, 0, "Service command line is: " << WIN32_Service_Command_Line);
    } else
        debugs(1, 0, "Running on " << WIN32_OS_string);

#endif

    debugs(1, 1, "Process ID " << getpid());

    debugs(1, 1, "With " << Squid_MaxFD << " file descriptors available");

#ifdef _SQUID_MSWIN_

    debugs(1, 1, "With " << _getmaxstdio() << " CRT stdio descriptors available");

    if (WIN32_Socks_initialized)
        debugs(1, 1, "Windows sockets initialized");

#endif

    if (!configured_once)
        disk_init();		/* disk_init must go before ipcache_init() */

    ipcache_init();

    fqdncache_init();

    parseEtcHosts();

#if USE_DNSSERVERS

    dnsInit();

#else

    idnsInit();

#endif

    redirectInit();

    authenticateInit(&Config.authConfiguration);

    externalAclInit();

    useragentOpenLog();

    refererOpenLog();

    httpHeaderInitModule();	/* must go before any header processing (e.g. the one in errorInitialize) */

    httpReplyInitModule();	/* must go before accepting replies */

    errorInitialize();

    accessLogInit();

#if USE_IDENT

    identInit();

#endif
#ifdef SQUID_SNMP

    snmpInit();

#endif
#if MALLOC_DBG

    malloc_debug(0, malloc_debug_level);

#endif

    if (!configured_once) {
#if USE_UNLINKD
        unlinkdInit();
#endif

        urlInitialize();
        statInit();
        storeInit();
        mainSetCwd();
        /* after this point we want to see the mallinfo() output */
        do_mallinfo = 1;
        mimeInit(Config.mimeTablePathname);
        refreshInit();
#if DELAY_POOLS

        DelayPools::Init();
#endif

        FwdState::initModule();
        /* register the modules in the cache manager menus */
        accessLogRegisterWithCacheManager(manager);
        asnRegisterWithCacheManager(manager);
        authenticateRegisterWithCacheManager(&Config.authConfiguration, manager);
#if USE_CARP

        carpRegisterWithCacheManager(manager);
#endif

        cbdataRegisterWithCacheManager(manager);
        /* These use separate calls so that the comm loops can eventually
         * coexist.
         */
#ifdef USE_EPOLL

        commEPollRegisterWithCacheManager(manager);
#endif
#ifdef USE_KQUEUE

        commKQueueRegisterWithCacheManager(manager);
#endif
#ifdef USE_POLL

        commPollRegisterWithCacheManager(manager);
#endif
#ifdef USE_SELECT

        commSelectRegisterWithCacheManager(manager);
#endif

        clientdbRegisterWithCacheManager(manager);
#if DELAY_POOLS

        DelayPools::RegisterWithCacheManager(manager);
#endif

        DiskIOModule::RegisterAllModulesWithCacheManager(manager);
#if USE_DNSSERVERS

        dnsRegisterWithCacheManager(manager);
#endif

        eventInit(manager);
        externalAclRegisterWithCacheManager(manager);
        fqdncacheRegisterWithCacheManager(manager);
        FwdState::RegisterWithCacheManager(manager);
        httpHeaderRegisterWithCacheManager(manager);
#if !USE_DNSSERVERS

        idnsRegisterWithCacheManager(manager);
#endif

        ipcacheRegisterWithCacheManager(manager);
        Mem::RegisterWithCacheManager(manager);
        netdbRegisterWitHCacheManager(manager);
        PconnModule::GetInstance()->registerWithCacheManager(manager);
        redirectRegisterWithCacheManager(manager);
        refreshRegisterWithCacheManager(manager);
        statRegisterWithCacheManager(manager);
        storeDigestRegisterWithCacheManager(manager);
        StoreFileSystem::RegisterAllFsWithCacheManager(manager);
        storeRegisterWithCacheManager(manager);
        storeLogRegisterWithCacheManager(manager);
#if DEBUGSTRINGS

        StringRegistry::Instance().registerWithCacheManager(manager);
#endif

#if	USE_XPROF_STATS

        xprofRegisterWithCacheManager(manager);
#endif

    }

#if USE_WCCP
    wccpInit();

#endif
#if USE_WCCPv2

    wccp2Init();

#endif

    serverConnectionsOpen();

    neighbors_init();

    neighborsRegisterWithCacheManager(manager);

    if (Config.chroot_dir)
        no_suid();

    if (!configured_once)
        writePidFile();		/* write PID file */

#ifdef _SQUID_LINUX_THREADS_

    squid_signal(SIGQUIT, rotate_logs, SA_RESTART);

    squid_signal(SIGTRAP, sigusr2_handle, SA_RESTART);

#else

    squid_signal(SIGUSR1, rotate_logs, SA_RESTART);

    squid_signal(SIGUSR2, sigusr2_handle, SA_RESTART);

#endif

    squid_signal(SIGHUP, reconfigure, SA_RESTART);

    squid_signal(SIGTERM, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);

    squid_signal(SIGINT, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);

#ifdef SIGTTIN

    squid_signal(SIGTTIN, shut_down, SA_NODEFER | SA_RESETHAND | SA_RESTART);

#endif

    memCheckInit();

    debugs(1, 1, "Ready to serve requests.");

    if (!configured_once) {
        eventAdd("storeMaintain", Store::Maintain, NULL, 1.0, 1);

        if (Config.onoff.announce)
            eventAdd("start_announce", start_announce, NULL, 3600.0, 1);

        eventAdd("ipcache_purgelru", ipcache_purgelru, NULL, 10.0, 1);

        eventAdd("fqdncache_purgelru", fqdncache_purgelru, NULL, 15.0, 1);

#if USE_XPROF_STATS

        eventAdd("cpuProfiling", xprof_event, NULL, 1.0, 1);

#endif

        eventAdd("memPoolCleanIdlePools", Mem::CleanIdlePools, NULL, 15.0, 1);

        eventAdd("commCheckHalfClosed", commCheckHalfClosed, NULL, 1.0, false);
    }

    configured_once = 1;
}

#if USE_WIN32_SERVICE
/* When USE_WIN32_SERVICE is defined, the main function is placed in win32.cc */
extern "C" void WINAPI
    SquidWinSvcMain(int argc, char **argv)
{
    SquidMain(argc, argv);
}

int
SquidMain(int argc, char **argv)
#else
int
main(int argc, char **argv)
#endif
{
    mode_t oldmask;
#ifdef _SQUID_WIN32_

    int WIN32_init_err;
#endif

#if HAVE_SBRK

    sbrk_start = sbrk(0);
#endif

    Debug::parseOptions("ALL,1");
    debug_log = stderr;

#if defined(SQUID_MAXFD_LIMIT)

    if (SQUID_MAXFD_LIMIT < Squid_MaxFD)
        Squid_MaxFD = SQUID_MAXFD_LIMIT;

#endif

#ifdef _SQUID_WIN32_

    if ((WIN32_init_err = WIN32_Subsystem_Init(&argc, &argv)))
        return WIN32_init_err;

#endif

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

    /*
     * The plan here is to set the umask to 007 (deny others for
     * read,write,execute), but only if the umask is not already
     * set.  Unfortunately, there is no way to get the current
     * umask value without setting it.
     */
    oldmask = umask(S_IRWXO);

    if (oldmask)
        umask(oldmask);

    memset(&local_addr, '\0', sizeof(struct IN_ADDR));

    safe_inet_addr(localhost, &local_addr);

    memset(&any_addr, '\0', sizeof(struct IN_ADDR));

    safe_inet_addr("0.0.0.0", &any_addr);

    memset(&no_addr, '\0', sizeof(struct IN_ADDR));

    safe_inet_addr("255.255.255.255", &no_addr);

    squid_srandom(time(NULL));

    getCurrentTime();

    squid_start = current_time;

    failure_notify = fatal_dump;

#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_START_PENDING, 10000);

#endif

    mainParseOptions(argc, argv);

#if USE_WIN32_SERVICE

    if (opt_install_service)
    {
        WIN32_InstallService();
        return 0;
    }

    if (opt_remove_service)
    {
        WIN32_RemoveService();
        return 0;
    }

    if (opt_command_line)
    {
        WIN32_SetServiceCommandLine();
        return 0;
    }

#endif

    /* parse configuration file
     * note: in "normal" case this used to be called from mainInitialize() */
    {
        int parse_err;

        if (!ConfigFile)
            ConfigFile = xstrdup(DefaultConfigFile);

        assert(!configured_once);

        Mem::Init();

        storeFsInit();		/* required for config parsing */

        /* May not be needed for parsing, have not audited for such */
        DiskIOModule::SetupAllModules();

        /* Shouldn't be needed for config parsing, but have not audited for such */
        StoreFileSystem::SetupAllFs();

        /* we may want the parsing process to set this up in the future */
        Store::Root(new StoreController);

        parse_err = parseConfigFile(ConfigFile, manager);

        if (opt_parse_cfg_only)

            return parse_err;
    }
    if (-1 == opt_send_signal)
        if (checkRunningPid())
            exit(1);

#if TEST_ACCESS

    comm_init();

    comm_select_init();

    mainInitialize();

    test_access();

    return 0;

#endif

    /* send signal to running copy and exit */
    if (opt_send_signal != -1)
    {
        /* chroot if configured to run inside chroot */

        if (Config.chroot_dir) {
            if (chroot(Config.chroot_dir))
                fatal("failed to chroot");

            no_suid();
        } else {
            leave_suid();
        }

        sendSignal();
        /* NOTREACHED */
    }

    if (opt_create_swap_dirs)
    {
        /* chroot if configured to run inside chroot */

        if (Config.chroot_dir && chroot(Config.chroot_dir)) {
            fatal("failed to chroot");
        }

        setEffectiveUser();
        debugs(0, 0, "Creating Swap Directories");
        Store::Root().create();

        return 0;
    }

    if (!opt_no_daemon)
        watch_child(argv);

    setMaxFD();

    /* init comm module */
    comm_init();

    comm_select_init();

    if (opt_no_daemon)
    {
        /* we have to init fdstat here. */
        fd_open(0, FD_LOG, "stdin");
        fd_open(1, FD_LOG, "stdout");
        fd_open(2, FD_LOG, "stderr");
    }

#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_START_PENDING, 10000);

#endif

    mainInitialize();

#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_RUNNING, 0);

#endif

    /* main loop */
    EventLoop mainLoop;

    SignalDispatcher signal_dispatcher(mainLoop);

    mainLoop.registerDispatcher(&signal_dispatcher);

    /* TODO: stop requiring the singleton here */
    mainLoop.registerDispatcher(EventDispatcher::GetInstance());

    /* TODO: stop requiring the singleton here */
    mainLoop.registerEngine(EventScheduler::GetInstance());

    StoreRootEngine store_engine;

    mainLoop.registerEngine(&store_engine);

    CommDispatcher comm_dispatcher;

    mainLoop.registerDispatcher(&comm_dispatcher);

    CommSelectEngine comm_engine;

    mainLoop.registerEngine(&comm_engine);

    mainLoop.setPrimaryEngine(&comm_engine);

    /* use the standard time service */
    TimeEngine time_engine;

    mainLoop.setTimeService(&time_engine);

    mainLoop.run();

    if (mainLoop.errcount == 10)
        fatal_dump("Event loop exited with failure.");

    /* shutdown squid now */
    SquidShutdown();

    /* NOTREACHED */
    return 0;
}

static void
sendSignal(void)
{
    pid_t pid;
    debug_log = stderr;

    if (strcmp(Config.pidFilename, "none") == 0) {
        debugs(0, 1, "No pid_filename specified. Trusting you know what you are doing.");
    }

    pid = readPidFile();

    if (pid > 1) {
#if USE_WIN32_SERVICE

        if (opt_signal_service) {
            WIN32_sendSignal(opt_send_signal);
            exit(0);
        } else
#ifdef _SQUID_MSWIN_
        {
            fprintf(stderr, "%s: ERROR: Could not send ", appname);
            fprintf(stderr, "signal to Squid Service:\n");
            fprintf(stderr, "missing -n command line switch.\n");
            exit(1);
        }

        /* NOTREACHED */
#endif

#endif

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

#ifndef _SQUID_MSWIN_
/*
 * This function is run when Squid is in daemon mode, just
 * before the parent forks and starts up the child process.
 * It can be used for admin-specific tasks, such as notifying
 * someone that Squid is (re)started.
 */
static void
mainStartScript(const char *prog)
{
    char script[SQUID_MAXPATHLEN];
    char *t;
    size_t sl = 0;
    pid_t cpid;
    pid_t rpid;
    xstrncpy(script, prog, MAXPATHLEN);

    if ((t = strrchr(script, '/'))) {
        *(++t) = '\0';
        sl = strlen(script);
    }

    xstrncpy(&script[sl], squid_start_script, MAXPATHLEN - sl);

    if ((cpid = fork()) == 0) {
        /* child */
        execl(script, squid_start_script, (char *)NULL);
        _exit(-1);
    } else {
        do {
#ifdef _SQUID_NEXT_
            union wait status;
            rpid = wait3(&status, 0, NULL);
#else

            int status;
            rpid = waitpid(-1, &status, 0);
#endif

        } while (rpid != cpid);
    }
}

#endif /* _SQUID_MSWIN_ */

static int
checkRunningPid(void)
{
    pid_t pid;

    if (!debug_log)
        debug_log = stderr;

    pid = readPidFile();

    if (pid < 2)
        return 0;

    if (kill(pid, 0) < 0)
        return 0;

    debugs(0, 0, "Squid is already running!  Process ID " <<  pid);

    return 1;
}

static void
watch_child(char *argv[])
{
#ifndef _SQUID_MSWIN_
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
#ifdef TIOCNOTTY

    int i;
#endif

    int nullfd;

    if (*(argv[0]) == '(')
        return;

    openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

    if ((pid = fork()) < 0)
        syslog(LOG_ALERT, "fork failed: %s", xstrerror());
    else if (pid > 0)
        exit(0);

    if (setsid() < 0)
        syslog(LOG_ALERT, "setsid failed: %s", xstrerror());

    closelog();

#ifdef TIOCNOTTY

    if ((i = open("/dev/tty", O_RDWR | O_TEXT)) >= 0) {
        ioctl(i, TIOCNOTTY, NULL);
        close(i);
    }

#endif

    /*
     * RBCOLLINS - if cygwin stackdumps when squid is run without
     * -N, check the cygwin1.dll version, it needs to be AT LEAST
     * 1.1.3.  execvp had a bit overflow error in a loop..
     */
    /* Connect stdio to /dev/null in daemon mode */
    nullfd = open(_PATH_DEVNULL, O_RDWR | O_TEXT);

    if (nullfd < 0)
        fatalf(_PATH_DEVNULL " %s\n", xstrerror());

    dup2(nullfd, 0);

    if (opt_debug_stderr < 0) {
        dup2(nullfd, 1);
        dup2(nullfd, 2);
    }

    for (;;) {
        mainStartScript(argv[0]);

        if ((pid = fork()) == 0) {
            /* child */
            openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
            prog = xstrdup(argv[0]);
            argv[0] = xstrdup("(squid)");
            execvp(prog, argv);
            syslog(LOG_ALERT, "execvp failed: %s", xstrerror());
        }

        /* parent */
        openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

        syslog(LOG_NOTICE, "Squid Parent: child process %d started", pid);

        time(&start);

        squid_signal(SIGINT, SIG_IGN, SA_RESTART);

#ifdef _SQUID_NEXT_

        pid = wait3(&status, 0, NULL);

#else

        pid = waitpid(-1, &status, 0);

#endif

        time(&stop);

        if (WIFEXITED(status)) {
            syslog(LOG_NOTICE,
                   "Squid Parent: child process %d exited with status %d",
                   pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            syslog(LOG_NOTICE,
                   "Squid Parent: child process %d exited due to signal %d",
                   pid, WTERMSIG(status));
        } else {
            syslog(LOG_NOTICE, "Squid Parent: child process %d exited", pid);
        }

        if (stop - start < 10)
            failcount++;
        else
            failcount = 0;

        if (failcount == 5) {
            syslog(LOG_ALERT, "Exiting due to repeated, frequent failures");
            exit(1);
        }

        if (WIFEXITED(status))
            if (WEXITSTATUS(status) == 0)
                exit(0);

        if (WIFSIGNALED(status)) {
            switch (WTERMSIG(status)) {

            case SIGKILL:
                exit(0);
                break;

            case SIGINT:
            case SIGTERM:
		syslog(LOG_ALERT, "Exiting due to unexpected forced shutdown");
                exit(1);
                break;

            default:
                break;
            }
        }

        squid_signal(SIGINT, SIG_DFL, SA_RESTART);
        sleep(3);
    }

    /* NOTREACHED */
#endif /* _SQUID_MSWIN_ */

}

static void
SquidShutdown()
{
#if USE_WIN32_SERVICE
    WIN32_svcstatusupdate(SERVICE_STOP_PENDING, 10000);
#endif

    debugs(1, 1, "Shutting down...");
#if USE_DNSSERVERS

    dnsShutdown();
#else

    idnsShutdown();
#endif

    redirectShutdown();
    externalAclShutdown();
    icpConnectionClose();
#if USE_HTCP

    htcpSocketClose();
#endif
#ifdef SQUID_SNMP

    snmpConnectionClose();
#endif
#if USE_WCCP

    wccpConnectionClose();
#endif
#if USE_WCCPv2

    wccp2ConnectionClose();
#endif

    releaseServerSockets();
    commCloseAllSockets();
#if DELAY_POOLS

    DelayPools::FreePools();
#endif

    authenticateShutdown();
#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_STOP_PENDING, 10000);
#endif

    Store::Root().sync(); /* Flush pending object writes/unlinks */
#if USE_UNLINKD

    unlinkdClose();	  /* after sync/flush */
#endif

    storeDirWriteCleanLogs(0);
    PrintRusage();
    dumpMallocStats();
    Store::Root().sync();		/* Flush log writes */
    storeLogClose();
    accessLogClose();
    useragentLogClose();
    refererCloseLog();
#if WIP_FWD_LOG

    fwdUninit();
#endif

    Store::Root().sync();		/* Flush log close */
    StoreFileSystem::FreeAllFs();
    DiskIOModule::FreeAllModules();
#if LEAK_CHECK_MODE && 0 /* doesn't work at the moment */

    configFreeMemory();
    storeFreeMemory();
    /*stmemFreeMemory(); */
    netdbFreeMemory();
    ipcacheFreeMemory();
    fqdncacheFreeMemory();
    asnFreeMemory();
    clientdbFreeMemory();
    httpHeaderCleanModule();
    statFreeMemory();
    eventFreeMemory();
    mimeFreeMemory();
    errorClean();
#endif
#if !XMALLOC_TRACE

    if (opt_no_daemon) {
        file_close(0);
        file_close(1);
        file_close(2);
    }

#endif
    fdDumpOpen();

    comm_exit();

    memClean();

#if XMALLOC_TRACE

    xmalloc_find_leaks();

    debugs(1, 0, "Memory used after shutdown: " << xmalloc_total);

#endif
#if MEM_GEN_TRACE

    log_trace_done();

#endif

    if (Config.pidFilename && strcmp(Config.pidFilename, "none") != 0) {
        enter_suid();
        safeunlink(Config.pidFilename, 0);
        leave_suid();
    }

    debugs(1, 1, "Squid Cache (Version " << version_string << "): Exiting normally.");

    /*
     * DPW 2006-10-23
     * We used to fclose(debug_log) here if it was set, but then
     * we forgot to set it to NULL.  That caused some coredumps
     * because exit() ends up calling a bunch of destructors and
     * such.   So rather than forcing the debug_log to close, we'll
     * leave it open so that those destructors can write some
     * debugging if necessary.  The file will be closed anyway when
     * the process truly exits.
     */

    exit(shutdown_status);
}

