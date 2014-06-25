/*
 * DEBUG: section 01    Startup and Main Loop
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
#include "acl/Acl.h"
#include "acl/Asn.h"
#include "AuthReg.h"
#include "base/RunnersRegistry.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "carp.h"
#include "client_db.h"
#include "client_side.h"
#include "comm.h"
#include "ConfigParser.h"
#include "CpuAffinity.h"
#include "disk.h"
#include "DiskIO/DiskIOModule.h"
#include "errorpage.h"
#include "event.h"
#include "EventLoop.h"
#include "ExternalACL.h"
#include "fd.h"
#include "format/Token.h"
#include "fs/Module.h"
#include "fqdncache.h"
#include "FwdState.h"
#include "globals.h"
#include "htcp.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "icmp/IcmpSquid.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "ident/Ident.h"
#include "ipcache.h"
#include "ipc/Coordinator.h"
#include "ipc/Kids.h"
#include "ipc/Strand.h"
#include "ip/tools.h"
#include "Mem.h"
#include "MemPool.h"
#include "mime.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerSelectState.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
#include "profiler/Profiler.h"
#include "redirect.h"
#include "refresh.h"
#include "send-announce.h"
#include "store_log.h"
#include "tools.h"
#include "SquidConfig.h"
#include "SquidDns.h"
#include "SquidTime.h"
#include "stat.h"
#include "StatCounters.h"
#include "StoreFileSystem.h"
#include "Store.h"
#include "SwapDir.h"
#include "unlinkd.h"
#include "URL.h"
#include "wccp.h"
#include "wccp2.h"
#include "WinSvc.h"

#if USE_ADAPTATION
#include "adaptation/Config.h"
#endif
#if USE_ECAP
#include "adaptation/ecap/Config.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/Config.h"
#include "adaptation/icap/icap_log.h"
#endif
#if USE_AUTH
#include "auth/Gadgets.h"
#endif
#if USE_DELAY_POOLS
#include "ClientDelayConfig.h"
#endif
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif
#if USE_LOADABLE_MODULES
#include "LoadableModules.h"
#endif
#if USE_SSL_CRTD
#include "ssl/certificate_db.h"
#endif
#if USE_SSL
#include "ssl/helper.h"
#include "ssl/context_storage.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/Config.h"
#endif
#if USE_ECAP
#include "adaptation/ecap/Config.h"
#endif
#if USE_ADAPTATION
#include "adaptation/Config.h"
#endif
#if USE_SQUID_ESI
#include "esi/Module.h"
#endif
#if SQUID_SNMP
#include "snmp_core.h"
#endif

#if HAVE_PATHS_H
#include <paths.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

#if USE_WIN32_SERVICE
#include <process.h>

static int opt_install_service = FALSE;
static int opt_remove_service = FALSE;
static int opt_signal_service = FALSE;
static int opt_command_line = FALSE;
void WIN32_svcstatusupdate(DWORD, DWORD);
void WINAPI WIN32_svcHandler(DWORD);
#endif

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

static int RotateSignal = -1;
static int ReconfigureSignal = -1;
static int ShutdownSignal = -1;

static void mainRotate(void);
static void mainReconfigureStart(void);
static void mainReconfigureFinish(void*);
static void mainInitialize(void);
static void usage(void);
static void mainParseOptions(int argc, char *argv[]);
static void sendSignal(void);
static void serverConnectionsOpen(void);
static void serverConnectionsClose(void);
static void watch_child(char **);
static void setEffectiveUser(void);
#if MEM_GEN_TRACE
void log_trace_done();
void log_trace_init(char *);
#endif
static void SquidShutdown(void);
static void mainSetCwd(void);
static int checkRunningPid(void);

#if !_SQUID_WINDOWS_
static const char *squid_start_script = "squid_start";
#endif

#if TEST_ACCESS
#include "test_access.c"
#endif

/** temporary thunk across to the unrefactored store interface */

class StoreRootEngine : public AsyncEngine
{

public:
    int checkEvents(int timeout) {
        Store::Root().callback();
        return EVENT_IDLE;
    };
};

class SignalEngine: public AsyncEngine
{

public:
    SignalEngine(EventLoop &evtLoop) : loop(evtLoop) {}
    virtual int checkEvents(int timeout);

private:
    static void StopEventLoop(void * data) {
        static_cast<SignalEngine *>(data)->loop.stop();
    }

    void doShutdown(time_t wait);

    EventLoop &loop;
};

int
SignalEngine::checkEvents(int timeout)
{
    PROF_start(SignalEngine_checkEvents);

    if (do_reconfigure) {
        mainReconfigureStart();
        do_reconfigure = 0;
    } else if (do_rotate) {
        mainRotate();
        do_rotate = 0;
    } else if (do_shutdown) {
        doShutdown(do_shutdown > 0 ? (int) Config.shutdownLifetime : 0);
        do_shutdown = 0;
    }
    BroadcastSignalIfAny(DebugSignal);
    BroadcastSignalIfAny(RotateSignal);
    BroadcastSignalIfAny(ReconfigureSignal);
    BroadcastSignalIfAny(ShutdownSignal);

    PROF_stop(SignalEngine_checkEvents);
    return EVENT_IDLE;
}

void
SignalEngine::doShutdown(time_t wait)
{
    debugs(1, DBG_IMPORTANT, "Preparing for shutdown after " << statCounter.client_http.requests << " requests");
    debugs(1, DBG_IMPORTANT, "Waiting " << wait << " seconds for active connections to finish");

    shutting_down = 1;

#if USE_WIN32_SERVICE
    WIN32_svcstatusupdate(SERVICE_STOP_PENDING, (wait + 1) * 1000);
#endif

    /* run the closure code which can be shared with reconfigure */
    serverConnectionsClose();
#if USE_AUTH
    /* detach the auth components (only do this on full shutdown) */
    Auth::Scheme::FreeAll();
#endif
    eventAdd("SquidShutdown", &StopEventLoop, this, (double) (wait + 1), 1, false);
}

static void
usage(void)
{
    fprintf(stderr,
#if USE_WIN32_SERVICE
            "Usage: %s [-cdhirvzCFNRVYX] [-s | -l facility] [-f config-file] [-[au] port] [-k signal] [-n name] [-O CommandLine]\n"
#else
            "Usage: %s [-cdhvzCFNRVYX] [-s | -l facility] [-f config-file] [-[au] port] [-k signal]\n"
#endif
            "       -a port   Specify HTTP port number (default: %d).\n"
            "       -d level  Write debugging to stderr also.\n"
            "       -f file   Use given config-file instead of\n"
            "                 %s\n"
            "       -h        Print help message.\n"
#if USE_WIN32_SERVICE
            "       -i        Installs as a Windows Service (see -n option).\n"
#endif
            "       -k reconfigure|rotate|shutdown|"
#ifdef SIGTTIN
            "restart|"
#endif
            "interrupt|kill|debug|check|parse\n"
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
            "       -z        Create missing swap directories and then exit.\n"
            "       -C        Do not catch fatal signals.\n"
            "       -D        OBSOLETE. Scheduled for removal.\n"
            "       -F        Don't serve any requests until store is rebuilt.\n"
            "       -N        No daemon mode.\n"
#if USE_WIN32_SERVICE
            "       -O options\n"
            "                 Set Windows Service Command line options in Registry.\n"
#endif
            "       -R        Do not set REUSEADDR on port.\n"
            "       -S        Double-check swap during rebuild.\n"
            "       -X        Force full debugging.\n"
            "       -Y        Only return UDP_HIT or UDP_MISS_NOFETCH during fast reload.\n",
            APP_SHORTNAME, CACHE_HTTP_PORT, DefaultConfigFile, CACHE_ICP_PORT);
    exit(1);
}

/**
 * Parse the parameters received via command line interface.
 *
 \param argc   Number of options received on command line
 \param argv   List of parameters received on command line
 */
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

        switch (c) {

        case 'C':
            /** \par C
             * Unset/disabel global option for catchign signals. opt_catch_signals */
            opt_catch_signals = 0;
            break;

        case 'D':
            /** \par D
             * OBSOLETE: WAS: override to prevent optional startup DNS tests. */
            debugs(1,DBG_CRITICAL, "WARNING: -D command-line option is obsolete.");
            break;

        case 'F':
            /** \par F
             * Set global option for foreground rebuild. opt_foreground_rebuild */
            opt_foreground_rebuild = 1;
            break;

        case 'N':
            /** \par N
             * Set global option for 'no_daemon' mode. opt_no_daemon */
            opt_no_daemon = 1;
            break;

#if USE_WIN32_SERVICE

        case 'O':
            /** \par O
             * Set global option. opt_command_lin and WIN32_Command_Line */
            opt_command_line = 1;
            WIN32_Command_Line = xstrdup(optarg);
            break;
#endif

        case 'R':
            /** \par R
             * Unset/disable global option opt_reuseaddr */
            opt_reuseaddr = 0;
            break;

        case 'S':
            /** \par S
             * Set global option opt_store_doublecheck */
            opt_store_doublecheck = 1;
            break;

        case 'X':
            /** \par X
             * Force full debugging */
            Debug::parseOptions("rotate=0 ALL,9");
            Debug::override_X = 1;
            sigusr2_handle(SIGUSR2);
            break;

        case 'Y':
            /** \par Y
             * Set global option opt_reload_hit_only */
            opt_reload_hit_only = 1;
            break;

#if USE_WIN32_SERVICE

        case 'i':
            /** \par i
             * Set global option opt_install_service (to TRUE) */
            opt_install_service = TRUE;
            break;
#endif

        case 'a':
            /** \par a
             * Add optional HTTP port as given following the option */
            add_http_port(optarg);
            break;

        case 'd':
            /** \par d
             * Set global option Debug::log_stderr to the number given follwoign the option */
            Debug::log_stderr = atoi(optarg);
            break;

        case 'f':
            /** \par f
             * Load the file given instead of the default squid.conf. */
            xfree(ConfigFile);
            ConfigFile = xstrdup(optarg);
            break;

        case 'k':
            /** \par k
             * Run the administrative action given following the option */

            /** \li When its an unknown option display the usage help. */
            if ((int) strlen(optarg) < 1)
                usage();

            if (!strncmp(optarg, "reconfigure", strlen(optarg)))
                /** \li On reconfigure send SIGHUP. */
                opt_send_signal = SIGHUP;
            else if (!strncmp(optarg, "rotate", strlen(optarg)))
                /** \li On rotate send SIGQUIT or SIGUSR1. */
#if defined(_SQUID_LINUX_THREADS_)
                opt_send_signal = SIGQUIT;
#else
                opt_send_signal = SIGUSR1;
#endif

            else if (!strncmp(optarg, "debug", strlen(optarg)))
                /** \li On debug send SIGTRAP or SIGUSR2. */
#if defined(_SQUID_LINUX_THREADS_)
                opt_send_signal = SIGTRAP;
#else
                opt_send_signal = SIGUSR2;
#endif

            else if (!strncmp(optarg, "shutdown", strlen(optarg)))
                /** \li On shutdown send SIGTERM. */
                opt_send_signal = SIGTERM;
            else if (!strncmp(optarg, "interrupt", strlen(optarg)))
                /** \li On interrupt send SIGINT. */
                opt_send_signal = SIGINT;
            else if (!strncmp(optarg, "kill", strlen(optarg)))
                /** \li On kill send SIGKILL. */
                opt_send_signal = SIGKILL;

#ifdef SIGTTIN

            else if (!strncmp(optarg, "restart", strlen(optarg)))
                /** \li On restart send SIGTTIN. (exit and restart by parent) */
                opt_send_signal = SIGTTIN;

#endif

            else if (!strncmp(optarg, "check", strlen(optarg)))
                /** \li On check send 0 / SIGNULL. */
                opt_send_signal = 0;	/* SIGNULL */
            else if (!strncmp(optarg, "parse", strlen(optarg)))
                /** \li On parse set global flag to re-parse the config file only. */
                opt_parse_cfg_only = 1;
            else
                usage();

            break;

        case 'm':
            /** \par m
             * Set global malloc_debug_level to the value given following the option.
             * if none is given it toggles the xmalloc_trace option on/off */
            if (optarg) {
#if MALLOC_DBG
                malloc_debug_level = atoi(optarg);
#else
                fatal("Need to add -DMALLOC_DBG when compiling to use -mX option");
#endif

            }
            break;

#if USE_WIN32_SERVICE

        case 'n':
            /** \par n
             * Set global option opt_signal_service (to TRUE).
             * Stores the additional parameter given in global WIN32_Service_name */
            xfree(WIN32_Service_name);

            WIN32_Service_name = xstrdup(optarg);

            opt_signal_service = TRUE;

            break;

        case 'r':
            /** \par r
             * Set global option opt_remove_service (to TRUE) */
            opt_remove_service = TRUE;

            break;

#endif

        case 'l':
            /** \par l
             * Stores the syslog facility name in global opt_syslog_facility
             * then performs actions for -s option. */
            xfree(opt_syslog_facility); // ignore any previous options sent
            opt_syslog_facility = xstrdup(optarg);

        case 's':
            /** \par s
             * Initialize the syslog for output */
#if HAVE_SYSLOG

            _db_set_syslog(opt_syslog_facility);

            break;

#else

            fatal("Logging to syslog not available on this platform");

            /* NOTREACHED */
#endif

        case 'u':
            /** \par u
             * Store the ICP port number given in global option icpPortNumOverride
             * ensuring its a positive number. */
            icpPortNumOverride = atoi(optarg);

            if (icpPortNumOverride < 0)
                icpPortNumOverride = 0;

            break;

        case 'v':
            /** \par v
             * Display squid version and build information. Then exit. */
            printf("Squid Cache: Version %s\n" ,version_string);
            if (strlen(SQUID_BUILD_INFO))
                printf("%s\n",SQUID_BUILD_INFO);
            printf( "configure options: %s\n", SQUID_CONFIGURE_OPTIONS);

#if USE_WIN32_SERVICE

            printf("Compiled as Windows System Service.\n");

#endif

            exit(0);

            /* NOTREACHED */

        case 'z':
            /** \par z
             * Set global option Debug::log_stderr and opt_create_swap_dirs */
            Debug::log_stderr = 1;
            opt_create_swap_dirs = 1;
            break;

        case 'h':

        case '?':

        default:
            /** \par h,?, or unknown
             * \copydoc usage() */
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
    RotateSignal = sig;
#if !_SQUID_WINDOWS_
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
    ReconfigureSignal = sig;
#if !_SQUID_WINDOWS_
#if !HAVE_SIGACTION

    signal(sig, reconfigure);
#endif
#endif
}

void
shut_down(int sig)
{
    do_shutdown = sig == SIGINT ? -1 : 1;
    ShutdownSignal = sig;
#ifdef SIGTTIN

    if (SIGTTIN == sig)
        shutdown_status = 1;

#endif

    const pid_t ppid = getppid();

    if (!IamMasterProcess() && ppid > 1) {
        // notify master that we are shutting down
        if (kill(ppid, SIGUSR1) < 0)
            debugs(1, DBG_IMPORTANT, "Failed to send SIGUSR1 to master process,"
                   " pid " << ppid << ": " << xstrerror());
    }

#if !_SQUID_WINDOWS_
#if KILL_PARENT_OPT

    if (!IamMasterProcess() && ppid > 1) {
        debugs(1, DBG_IMPORTANT, "Killing master process, pid " << ppid);

        if (kill(ppid, sig) < 0)
            debugs(1, DBG_IMPORTANT, "kill " << ppid << ": " << xstrerror());
    }

#endif /* KILL_PARENT_OPT */
#if SA_RESETHAND == 0
    signal(SIGTERM, SIG_DFL);

    signal(SIGINT, SIG_DFL);

#endif
#endif
}

static void
serverConnectionsOpen(void)
{
    if (IamPrimaryProcess()) {
#if USE_WCCP
        wccpConnectionOpen();
#endif

#if USE_WCCPv2

        wccp2ConnectionOpen();
#endif
    }
    // start various proxying services if we are responsible for them
    if (IamWorkerProcess()) {
        clientOpenListenSockets();
        icpOpenPorts();
#if USE_HTCP
        htcpOpenPorts();
#endif
#if SQUID_SNMP
        snmpOpenPorts();
#endif

        icmpEngine.Open();
        netdbInit();
        asnInit();
        ACL::Initialize();
        peerSelectInit();

        carpInit();
#if USE_AUTH
        peerUserHashInit();
#endif
        peerSourceHashInit();
    }
}

static void
serverConnectionsClose(void)
{
    assert(shutting_down || reconfiguring);

    if (IamPrimaryProcess()) {
#if USE_WCCP

        wccpConnectionClose();
#endif
#if USE_WCCPv2

        wccp2ConnectionClose();
#endif
    }
    if (IamWorkerProcess()) {
        clientHttpConnectionsClose();
        icpConnectionShutdown();
#if USE_HTCP
        htcpSocketShutdown();
#endif

        icmpEngine.Close();
#if SQUID_SNMP
        snmpClosePorts();
#endif

        asnFreeMemory();
    }
}

static void
mainReconfigureStart(void)
{
    debugs(1, DBG_IMPORTANT, "Reconfiguring Squid Cache (version " << version_string << ")...");
    reconfiguring = 1;

    // Initiate asynchronous closing sequence
    serverConnectionsClose();
    icpClosePorts();
#if USE_HTCP
    htcpClosePorts();
#endif
    dnsShutdown();
#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Shutdown();
#endif
#if USE_SSL
    if (Ssl::CertValidationHelper::GetInstance())
        Ssl::CertValidationHelper::GetInstance()->Shutdown();
    Ssl::TheGlobalContextStorage.reconfigureStart();
#endif
    redirectShutdown();
#if USE_AUTH
    authenticateReset();
#endif
    externalAclShutdown();
    storeDirCloseSwapLogs();
    storeLogClose();
    accessLogClose();
#if ICAP_CLIENT
    icapLogClose();
#endif

    eventAdd("mainReconfigureFinish", &mainReconfigureFinish, NULL, 0, 1,
             false);
}

static void
mainReconfigureFinish(void *)
{
    debugs(1, 3, "finishing reconfiguring");

    errorClean();
    enter_suid();		/* root to read config file */

    // we may have disabled the need for PURGE
    if (Config2.onoff.enable_purge)
        Config2.onoff.enable_purge = 2;

    // parse the config returns a count of errors encountered.
    const int oldWorkers = Config.workers;
    if ( parseConfigFile(ConfigFile) != 0) {
        // for now any errors are a fatal condition...
        self_destruct();
    }
    if (oldWorkers != Config.workers) {
        debugs(1, DBG_CRITICAL, "WARNING: Changing 'workers' (from " <<
               oldWorkers << " to " << Config.workers <<
               ") requires a full restart. It has been ignored by reconfigure.");
        Config.workers = oldWorkers;
    }

    if (IamPrimaryProcess())
        CpuAffinityCheck();
    CpuAffinityReconfigure();

    setUmask(Config.umask);
    Mem::Report();
    setEffectiveUser();
    _db_init(Debug::cache_log, Debug::debugOptions);
    ipcache_restart();		/* clear stuck entries */
    fqdncache_restart();	/* sigh, fqdncache too */
    parseEtcHosts();
    errorInitialize();		/* reload error pages */
    accessLogInit();

#if USE_LOADABLE_MODULES
    LoadableModulesConfigure(Config.loadable_module_names);
#endif

#if USE_ADAPTATION
    bool enableAdaptation = false;
#if ICAP_CLIENT
    Adaptation::Icap::TheConfig.finalize();
    enableAdaptation = Adaptation::Icap::TheConfig.onoff || enableAdaptation;
#endif
#if USE_ECAP
    Adaptation::Ecap::TheConfig.finalize(); // must be after we load modules
    enableAdaptation = Adaptation::Ecap::TheConfig.onoff || enableAdaptation;
#endif
    Adaptation::Config::Finalize(enableAdaptation);
#endif

#if ICAP_CLIENT
    icapLogOpen();
#endif
    storeLogOpen();
    dnsInit();
#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Init();
#endif
#if USE_SSL
    if (Ssl::CertValidationHelper::GetInstance())
        Ssl::CertValidationHelper::GetInstance()->Init();
#endif

    redirectInit();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig);
#endif
    externalAclInit();

    if (IamPrimaryProcess()) {
#if USE_WCCP

        wccpInit();
#endif
#if USE_WCCPv2

        wccp2Init();
#endif
    }

    serverConnectionsOpen();

    neighbors_init();

    storeDirOpenSwapLogs();

    mimeInit(Config.mimeTablePathname);

    if (unlinkdNeeded())
        unlinkdInit();

#if USE_DELAY_POOLS
    Config.ClientDelay.finalize();
#endif

    if (Config.onoff.announce) {
        if (!eventFind(start_announce, NULL))
            eventAdd("start_announce", start_announce, NULL, 3600.0, 1);
    } else {
        if (eventFind(start_announce, NULL))
            eventDelete(start_announce, NULL);
    }

    writePidFile();		/* write PID file */

    reconfiguring = 0;
}

static void
mainRotate(void)
{
    icmpEngine.Close();
#if USE_DNSHELPER
    dnsShutdown();
#endif
    redirectShutdown();
#if USE_AUTH
    authenticateRotate();
#endif
    externalAclShutdown();

    _db_rotate_log();		/* cache.log */
    storeDirWriteCleanLogs(1);
    storeLogRotate();		/* store.log */
    accessLogRotate();		/* access.log */
#if ICAP_CLIENT
    icapLogRotate();               /*icap.log*/
#endif
    icmpEngine.Open();
#if USE_DNSHELPER
    dnsInit();
#endif
    redirectInit();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig);
#endif
    externalAclInit();
}

static void
setEffectiveUser(void)
{
    keepCapabilities();
    leave_suid();		/* Run as non privilegied user */
#if _SQUID_OS2_

    return;
#endif

    if (geteuid() == 0) {
        debugs(0, DBG_CRITICAL, "Squid is not safe to run as root!  If you must");
        debugs(0, DBG_CRITICAL, "start Squid as root, then you must configure");
        debugs(0, DBG_CRITICAL, "it to run as a non-priveledged user with the");
        debugs(0, DBG_CRITICAL, "'cache_effective_user' option in the config file.");
        fatal("Don't run Squid as root, set 'cache_effective_user'!");
    }
}

/// changes working directory, providing error reporting
static bool
mainChangeDir(const char *dir)
{
    if (chdir(dir) == 0)
        return true;

    debugs(50, DBG_CRITICAL, "cannot change current directory to " << dir <<
           ": " << xstrerror());
    return false;
}

/// set the working directory.
static void
mainSetCwd(void)
{
    static bool chrooted = false;
    if (Config.chroot_dir && !chrooted) {
        chrooted = true;

        if (chroot(Config.chroot_dir) != 0)
            fatalf("chroot to %s failed: %s", Config.chroot_dir, xstrerror());

        if (!mainChangeDir("/"))
            fatalf("chdir to / after chroot to %s failed", Config.chroot_dir);
    }

    if (Config.coredump_dir && strcmp("none", Config.coredump_dir) != 0) {
        if (mainChangeDir(Config.coredump_dir)) {
            debugs(0, DBG_IMPORTANT, "Set Current Directory to " << Config.coredump_dir);
            return;
        }
    }

    /* If we don't have coredump_dir or couldn't cd there, report current dir */
    char pathbuf[MAXPATHLEN];
    if (getcwd(pathbuf, MAXPATHLEN)) {
        debugs(0, DBG_IMPORTANT, "Current Directory is " << pathbuf);
    } else {
        debugs(50, DBG_CRITICAL, "WARNING: Can't find current directory, getcwd: " << xstrerror());
    }
}

static void
mainInitialize(void)
{
    /* chroot if configured to run inside chroot */
    mainSetCwd();

    if (opt_catch_signals) {
        squid_signal(SIGSEGV, death, SA_NODEFER | SA_RESETHAND);
        squid_signal(SIGBUS, death, SA_NODEFER | SA_RESETHAND);
    }

    squid_signal(SIGPIPE, SIG_IGN, SA_RESTART);
    squid_signal(SIGCHLD, sig_child, SA_NODEFER | SA_RESTART);

    setEffectiveUser();

    if (icpPortNumOverride != 1)
        Config.Port.icp = (unsigned short) icpPortNumOverride;

    _db_init(Debug::cache_log, Debug::debugOptions);

    fd_open(fileno(debug_log), FD_LOG, Debug::cache_log);

#if MEM_GEN_TRACE

    log_trace_init("/tmp/squid.alloc");

#endif

    debugs(1, DBG_CRITICAL, "Starting Squid Cache version " << version_string << " for " << CONFIG_HOST_TYPE << "...");

#if _SQUID_WINDOWS_
    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        debugs(1, DBG_CRITICAL, "Running as " << WIN32_Service_name << " Windows System Service on " << WIN32_OS_string);
        debugs(1, DBG_CRITICAL, "Service command line is: " << WIN32_Service_Command_Line);
    } else
        debugs(1, DBG_CRITICAL, "Running on " << WIN32_OS_string);
#endif

    debugs(1, DBG_IMPORTANT, "Process ID " << getpid());

    debugs(1, DBG_IMPORTANT, "Process Roles:" << ProcessRoles());

    setSystemLimits();
    debugs(1, DBG_IMPORTANT, "With " << Squid_MaxFD << " file descriptors available");

#if _SQUID_WINDOWS_

    debugs(1, DBG_IMPORTANT, "With " << _getmaxstdio() << " CRT stdio descriptors available");

    if (WIN32_Socks_initialized)
        debugs(1, DBG_IMPORTANT, "Windows sockets initialized");

    if (WIN32_OS_version > _WIN_OS_WINNT) {
        WIN32_IpAddrChangeMonitorInit();
    }

#endif

    if (!configured_once)
        disk_init();		/* disk_init must go before ipcache_init() */

    ipcache_init();

    fqdncache_init();

    parseEtcHosts();

    dnsInit();

#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Init();
#endif

#if USE_SSL
    if (Ssl::CertValidationHelper::GetInstance())
        Ssl::CertValidationHelper::GetInstance()->Init();
#endif

    redirectInit();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig);
#endif
    externalAclInit();

    httpHeaderInitModule();	/* must go before any header processing (e.g. the one in errorInitialize) */

    httpReplyInitModule();	/* must go before accepting replies */

    errorInitialize();

    accessLogInit();

#if ICAP_CLIENT
    icapLogOpen();
#endif

#if USE_IDENT
    Ident::Init();
#endif

#if SQUID_SNMP

    snmpInit();

#endif
#if MALLOC_DBG

    malloc_debug(0, malloc_debug_level);

#endif

    if (!configured_once) {
        if (unlinkdNeeded())
            unlinkdInit();

        urlInitialize();
        statInit();
        storeInit();
        mainSetCwd();
        /* after this point we want to see the mallinfo() output */
        do_mallinfo = 1;
        mimeInit(Config.mimeTablePathname);
        refreshInit();
#if USE_DELAY_POOLS
        DelayPools::Init();
#endif

        FwdState::initModule();
        /* register the modules in the cache manager menus */

        cbdataRegisterWithCacheManager();
        /* These use separate calls so that the comm loops can eventually
         * coexist.
         */

        eventInit();

        // TODO: pconn is a good candidate for new-style registration
        // PconnModule::GetInstance()->registerWithCacheManager();
        //   moved to PconnModule::PconnModule()
    }

    if (IamPrimaryProcess()) {
#if USE_WCCP
        wccpInit();

#endif
#if USE_WCCPv2

        wccp2Init();

#endif
    }

    serverConnectionsOpen();

    neighbors_init();

    // neighborsRegisterWithCacheManager(); //moved to neighbors_init()

    if (Config.chroot_dir)
        no_suid();

    if (!configured_once)
        writePidFile();		/* write PID file */

#if defined(_SQUID_LINUX_THREADS_)

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

#if USE_LOADABLE_MODULES
    LoadableModulesConfigure(Config.loadable_module_names);
#endif

#if USE_ADAPTATION
    bool enableAdaptation = false;

    // We can remove this dependency on specific adaptation mechanisms
    // if we create a generic Registry of such mechanisms. Should we?
#if ICAP_CLIENT
    Adaptation::Icap::TheConfig.finalize();
    enableAdaptation = Adaptation::Icap::TheConfig.onoff || enableAdaptation;
#endif
#if USE_ECAP
    Adaptation::Ecap::TheConfig.finalize(); // must be after we load modules
    enableAdaptation = Adaptation::Ecap::TheConfig.onoff || enableAdaptation;
#endif
    // must be the last adaptation-related finalize
    Adaptation::Config::Finalize(enableAdaptation);
#endif

#if USE_SQUID_ESI
    Esi::Init();
#endif

#if USE_DELAY_POOLS
    Config.ClientDelay.finalize();
#endif

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
    }

    configured_once = 1;
}

/// unsafe main routine -- may throw
int SquidMain(int argc, char **argv);
/// unsafe main routine wrapper to catch exceptions
static int SquidMainSafe(int argc, char **argv);

#if USE_WIN32_SERVICE
/* When USE_WIN32_SERVICE is defined, the main function is placed in win32.cc */
extern "C" void WINAPI
SquidWinSvcMain(int argc, char **argv)
{
    SquidMainSafe(argc, argv);
}
#else
int
main(int argc, char **argv)
{
    return SquidMainSafe(argc, argv);
}
#endif

static int
SquidMainSafe(int argc, char **argv)
{
    try {
        return SquidMain(argc, argv);
    } catch (const std::exception &e) {
        debugs(1, DBG_CRITICAL, "FATAL: dying from an unhandled exception: " <<
               e.what());
        throw;
    } catch (...) {
        debugs(1, DBG_CRITICAL, "FATAL: dying from an unhandled exception.");
        throw;
    }
    return -1; // not reached
}

/// computes name and ID for the current kid process
static void
ConfigureCurrentKid(const char *processName)
{
    // kids are marked with parenthesis around their process names
    if (processName && processName[0] == '(') {
        if (const char *idStart = strrchr(processName, '-')) {
            KidIdentifier = atoi(idStart + 1);
            const size_t nameLen = idStart - (processName + 1);
            assert(nameLen < sizeof(TheKidName));
            xstrncpy(TheKidName, processName + 1, nameLen + 1);
            if (!strcmp(TheKidName, "squid-coord"))
                TheProcessKind = pkCoordinator;
            else if (!strcmp(TheKidName, "squid"))
                TheProcessKind = pkWorker;
            else if (!strcmp(TheKidName, "squid-disk"))
                TheProcessKind = pkDisker;
            else
                TheProcessKind = pkOther; // including coordinator
        }
    } else {
        xstrncpy(TheKidName, APP_SHORTNAME, sizeof(TheKidName));
        KidIdentifier = 0;
    }
}

int
SquidMain(int argc, char **argv)
{
    ConfigureCurrentKid(argv[0]);

    Debug::parseOptions(NULL);
    debug_log = stderr;

#if defined(SQUID_MAXFD_LIMIT)

    if (SQUID_MAXFD_LIMIT < Squid_MaxFD)
        Squid_MaxFD = SQUID_MAXFD_LIMIT;

#endif

    /* NOP under non-windows */
    int WIN32_init_err=0;
    if ((WIN32_init_err = WIN32_Subsystem_Init(&argc, &argv)))
        return WIN32_init_err;

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

    squid_srandom(time(NULL));

    getCurrentTime();

    squid_start = current_time;

    failure_notify = fatal_dump;

#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_START_PENDING, 10000);

#endif

    mainParseOptions(argc, argv);

    if (opt_parse_cfg_only) {
        Debug::parseOptions("ALL,1");
    }

#if USE_WIN32_SERVICE

    if (opt_install_service) {
        WIN32_InstallService();
        return 0;
    }

    if (opt_remove_service) {
        WIN32_RemoveService();
        return 0;
    }

    if (opt_command_line) {
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

        /* TODO: call the FS::Clean() in shutdown to do Fs cleanups */
        Fs::Init();

        /* May not be needed for parsing, have not audited for such */
        DiskIOModule::SetupAllModules();

        /* Shouldn't be needed for config parsing, but have not audited for such */
        StoreFileSystem::SetupAllFs();

        /* we may want the parsing process to set this up in the future */
        Store::Root(new StoreController);
        Auth::Init();      /* required for config parsing. NOP if !USE_AUTH */
        Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.

        Format::Token::Init(); // XXX: temporary. Use a runners registry of pre-parse runners instead.

        parse_err = parseConfigFile(ConfigFile);

        Mem::Report();

        if (opt_parse_cfg_only || parse_err > 0)
            return parse_err;
    }
    setUmask(Config.umask);
    if (-1 == opt_send_signal)
        if (checkRunningPid())
            exit(0);

#if TEST_ACCESS

    comm_init();

    mainInitialize();

    test_access();

    return 0;

#endif

    /* send signal to running copy and exit */
    if (opt_send_signal != -1) {
        /* chroot if configured to run inside chroot */
        mainSetCwd();
        if (Config.chroot_dir) {
            no_suid();
        } else {
            leave_suid();
        }

        sendSignal();
        /* NOTREACHED */
    }

    debugs(1,2, HERE << "Doing post-config initialization\n");
    leave_suid();
    ActivateRegistered(rrFinalizeConfig);
    ActivateRegistered(rrClaimMemoryNeeds);
    ActivateRegistered(rrAfterConfig);
    enter_suid();

    if (!opt_no_daemon && Config.workers > 0)
        watch_child(argv);

    if (opt_create_swap_dirs) {
        /* chroot if configured to run inside chroot */
        mainSetCwd();

        setEffectiveUser();
        debugs(0, DBG_CRITICAL, "Creating missing swap directories");
        Store::Root().create();

        return 0;
    }

    if (IamPrimaryProcess())
        CpuAffinityCheck();
    CpuAffinityInit();

    setMaxFD();

    /* init comm module */
    comm_init();

    if (opt_no_daemon) {
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

    SignalEngine signalEngine(mainLoop);

    mainLoop.registerEngine(&signalEngine);

    /* TODO: stop requiring the singleton here */
    mainLoop.registerEngine(EventScheduler::GetInstance());

    StoreRootEngine store_engine;

    mainLoop.registerEngine(&store_engine);

    CommSelectEngine comm_engine;

    mainLoop.registerEngine(&comm_engine);

    mainLoop.setPrimaryEngine(&comm_engine);

    /* use the standard time service */
    TimeEngine time_engine;

    mainLoop.setTimeService(&time_engine);

    if (IamCoordinatorProcess())
        AsyncJob::Start(Ipc::Coordinator::Instance());
    else if (UsingSmp() && (IamWorkerProcess() || IamDiskProcess()))
        AsyncJob::Start(new Ipc::Strand);

    /* at this point we are finished the synchronous startup. */
    starting_up = 0;

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
        debugs(0, DBG_IMPORTANT, "No pid_filename specified. Trusting you know what you are doing.");
    }

    pid = readPidFile();

    if (pid > 1) {
#if USE_WIN32_SERVICE
        if (opt_signal_service) {
            WIN32_sendSignal(opt_send_signal);
            exit(0);
        } else {
            fprintf(stderr, "%s: ERROR: Could not send ", APP_SHORTNAME);
            fprintf(stderr, "signal to Squid Service:\n");
            fprintf(stderr, "missing -n command line switch.\n");
            exit(1);
        }
        /* NOTREACHED */
#endif

        if (kill(pid, opt_send_signal) &&
                /* ignore permissions if just running check */
                !(opt_send_signal == 0 && errno == EPERM)) {
            fprintf(stderr, "%s: ERROR: Could not send ", APP_SHORTNAME);
            fprintf(stderr, "signal %d to process %d: %s\n",
                    opt_send_signal, (int) pid, xstrerror());
            exit(1);
        }
    } else {
        if (opt_send_signal != SIGTERM) {
            fprintf(stderr, "%s: ERROR: No running copy\n", APP_SHORTNAME);
            exit(1);
        } else {
            fprintf(stderr, "%s: No running copy\n", APP_SHORTNAME);
            exit(0);
        }
    }

    /* signal successfully sent */
    exit(0);
}

#if !_SQUID_WINDOWS_
/*
 * This function is run when Squid is in daemon mode, just
 * before the parent forks and starts up the child process.
 * It can be used for admin-specific tasks, such as notifying
 * someone that Squid is (re)started.
 */
static void
mainStartScript(const char *prog)
{
    char script[MAXPATHLEN];
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
#if _SQUID_NEXT_
            union wait status;
            rpid = wait4(cpid, &status, 0, NULL);
#else

            int status;
            rpid = waitpid(cpid, &status, 0);
#endif

        } while (rpid != cpid);
    }
}

#endif /* _SQUID_WINDOWS_ */

static int
checkRunningPid(void)
{
    // master process must start alone, but its kids processes may co-exist
    if (!IamMasterProcess())
        return 0;

    pid_t pid;

    if (!debug_log)
        debug_log = stderr;

    pid = readPidFile();

    if (pid < 2)
        return 0;

    if (kill(pid, 0) < 0)
        return 0;

    debugs(0, DBG_CRITICAL, "Squid is already running!  Process ID " <<  pid);

    return 1;
}

static void
watch_child(char *argv[])
{
#if !_SQUID_WINDOWS_
    char *prog;
#if _SQUID_NEXT_

    union wait status;
#else

    int status;
#endif

    pid_t pid;
#ifdef TIOCNOTTY

    int i;
#endif

    int nullfd;

    if (!IamMasterProcess())
        return;

    openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

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

    if (Debug::log_stderr < 0) {
        dup2(nullfd, 1);
        dup2(nullfd, 2);
    }

    // handle shutdown notifications from kids
    squid_signal(SIGUSR1, sig_shutdown, SA_RESTART);

    if (Config.workers > 128) {
        syslog(LOG_ALERT, "Suspiciously high workers value: %d",
               Config.workers);
        // but we keep going in hope that user knows best
    }
    TheKids.init();

    syslog(LOG_NOTICE, "Squid Parent: will start %d kids", (int)TheKids.count());

    // keep [re]starting kids until it is time to quit
    for (;;) {
        mainStartScript(argv[0]);

        // start each kid that needs to be [re]started; once
        for (int i = TheKids.count() - 1; i >= 0; --i) {
            Kid& kid = TheKids.get(i);
            if (!kid.shouldRestart())
                continue;

            if ((pid = fork()) == 0) {
                /* child */
                openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
                prog = argv[0];
                argv[0] = const_cast<char*>(kid.name().termedBuf());
                execvp(prog, argv);
                syslog(LOG_ALERT, "execvp failed: %s", xstrerror());
            }

            kid.start(pid);
            syslog(LOG_NOTICE, "Squid Parent: %s process %d started",
                   kid.name().termedBuf(), pid);
        }

        /* parent */
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

        squid_signal(SIGINT, SIG_IGN, SA_RESTART);

#if _SQUID_NEXT_

        pid = wait3(&status, 0, NULL);

#else

        pid = waitpid(-1, &status, 0);

#endif
        // Loop to collect all stopped kids before we go to sleep below.
        do {
            Kid* kid = TheKids.find(pid);
            if (kid) {
                kid->stop(status);
                if (kid->calledExit()) {
                    syslog(LOG_NOTICE,
                           "Squid Parent: %s process %d exited with status %d",
                           kid->name().termedBuf(),
                           kid->getPid(), kid->exitStatus());
                } else if (kid->signaled()) {
                    syslog(LOG_NOTICE,
                           "Squid Parent: %s process %d exited due to signal %d with status %d",
                           kid->name().termedBuf(),
                           kid->getPid(), kid->termSignal(), kid->exitStatus());
                } else {
                    syslog(LOG_NOTICE, "Squid Parent: %s process %d exited",
                           kid->name().termedBuf(), kid->getPid());
                }
                if (kid->hopeless()) {
                    syslog(LOG_NOTICE, "Squid Parent: %s process %d will not"
                           " be restarted due to repeated, frequent failures",
                           kid->name().termedBuf(), kid->getPid());
                }
            } else {
                syslog(LOG_NOTICE, "Squid Parent: unknown child process %d exited", pid);
            }
#if _SQUID_NEXT_
        } while ((pid = wait3(&status, WNOHANG, NULL)) > 0);
#else
        }
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0);
#endif

        if (!TheKids.someRunning() && !TheKids.shouldRestartSome()) {
            leave_suid();
            DeactivateRegistered(rrAfterConfig);
            DeactivateRegistered(rrClaimMemoryNeeds);
            DeactivateRegistered(rrFinalizeConfig);
            enter_suid();

            if (TheKids.someSignaled(SIGINT) || TheKids.someSignaled(SIGTERM)) {
                syslog(LOG_ALERT, "Exiting due to unexpected forced shutdown");
                exit(1);
            }

            if (TheKids.allHopeless()) {
                syslog(LOG_ALERT, "Exiting due to repeated, frequent failures");
                exit(1);
            }

            exit(0);
        }

        squid_signal(SIGINT, SIG_DFL, SA_RESTART);
        sleep(3);
    }

    /* NOTREACHED */
#endif /* _SQUID_WINDOWS_ */

}

static void
SquidShutdown()
{
    /* XXX: This function is called after the main loop has quit, which
     * means that no AsyncCalls would be called, including close handlers.
     * TODO: We need to close/shut/free everything that needs calls before
     * exiting the loop.
     */

#if USE_WIN32_SERVICE
    WIN32_svcstatusupdate(SERVICE_STOP_PENDING, 10000);
#endif

    debugs(1, DBG_IMPORTANT, "Shutting down...");
    dnsShutdown();
#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Shutdown();
#endif
#if USE_SSL
    if (Ssl::CertValidationHelper::GetInstance())
        Ssl::CertValidationHelper::GetInstance()->Shutdown();
#endif
    redirectShutdown();
    externalAclShutdown();
    icpClosePorts();
#if USE_HTCP
    htcpClosePorts();
#endif
#if SQUID_SNMP
    snmpClosePorts();
#endif
#if USE_WCCP

    wccpConnectionClose();
#endif
#if USE_WCCPv2

    wccp2ConnectionClose();
#endif

    releaseServerSockets();
    commCloseAllSockets();

#if USE_SQUID_ESI
    Esi::Clean();
#endif

#if USE_DELAY_POOLS
    DelayPools::FreePools();
#endif
#if USE_AUTH
    authenticateReset();
#endif
#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_STOP_PENDING, 10000);
#endif

    Store::Root().sync(); /* Flush pending object writes/unlinks */

    unlinkdClose();	  /* after sync/flush. NOP if !USE_UNLINKD */

    storeDirWriteCleanLogs(0);
    PrintRusage();
    dumpMallocStats();
    Store::Root().sync();		/* Flush log writes */
    storeLogClose();
    accessLogClose();
    Store::Root().sync();		/* Flush log close */
    StoreFileSystem::FreeAllFs();
    DiskIOModule::FreeAllModules();
    DeactivateRegistered(rrAfterConfig);
    DeactivateRegistered(rrClaimMemoryNeeds);
    DeactivateRegistered(rrFinalizeConfig);
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
    // clear StoreController
    Store::Root(NULL);

    fdDumpOpen();

    comm_exit();

    memClean();

#if MEM_GEN_TRACE

    log_trace_done();

#endif

    if (IamPrimaryProcess()) {
        if (Config.pidFilename && strcmp(Config.pidFilename, "none") != 0) {
            enter_suid();
            safeunlink(Config.pidFilename, 0);
            leave_suid();
        }
    }

    debugs(1, DBG_IMPORTANT, "Squid Cache (Version " << version_string << "): Exiting normally.");

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

