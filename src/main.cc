/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 01    Startup and Main Loop */

#include "squid.h"
#include "AccessLogEntry.h"
//#include "acl/Acl.h"
#include "acl/Asn.h"
#include "acl/forward.h"
#include "anyp/UriScheme.h"
#include "AuthReg.h"
#include "base/RunnersRegistry.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "CachePeer.h"
#include "carp.h"
#include "client_db.h"
#include "client_side.h"
#include "comm.h"
#include "ConfigParser.h"
#include "CpuAffinity.h"
#include "DiskIO/DiskIOModule.h"
#include "dns/forward.h"
#include "errorpage.h"
#include "event.h"
#include "EventLoop.h"
#include "ExternalACL.h"
#include "fd.h"
#include "format/Token.h"
#include "fqdncache.h"
#include "fs/Module.h"
#include "fs_io.h"
#include "FwdState.h"
#include "globals.h"
#include "htcp.h"
#include "http/Stream.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "icmp/IcmpSquid.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "ident/Ident.h"
#include "Instance.h"
#include "ip/tools.h"
#include "ipc/Coordinator.h"
#include "ipc/Kids.h"
#include "ipc/Strand.h"
#include "ipcache.h"
#include "mime.h"
#include "neighbors.h"
#include "parser/Tokenizer.h"
#include "pconn.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
#include "PeerSelectState.h"
#include "profiler/Profiler.h"
#include "redirect.h"
#include "refresh.h"
#include "sbuf/Stream.h"
#include "SBufStatsAction.h"
#include "send-announce.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "stat.h"
#include "StatCounters.h"
#include "Store.h"
#include "store/Disks.h"
#include "store_log.h"
#include "StoreFileSystem.h"
#include "tools.h"
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
#if USE_OPENSSL
#include "ssl/context_storage.h"
#include "ssl/helper.h"
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

#include <cerrno>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif
#if HAVE_PATHS_H
#include <paths.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#if USE_WIN32_SERVICE
#include <process.h>

static int opt_install_service = FALSE;
static int opt_remove_service = FALSE;
static int opt_command_line = FALSE;
void WIN32_svcstatusupdate(DWORD, DWORD);
void WINAPI WIN32_svcHandler(DWORD);
#endif

static int opt_signal_service = FALSE;
static char *opt_syslog_facility = NULL;
static int icpPortNumOverride = 1;  /* Want to detect "-u 0" */
static int configured_once = 0;
#if MALLOC_DBG
static int malloc_debug_level = 0;
#endif
static volatile int do_reconfigure = 0;
static volatile int do_rotate = 0;
static volatile int do_shutdown = 0;
static volatile int shutdown_status = 0;
static volatile int do_handle_stopped_child = 0;

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
static void SquidShutdown(void);
static void mainSetCwd(void);

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
    int checkEvents(int) {
        Store::Root().callback();
        return EVENT_IDLE;
    };
};

class SignalEngine: public AsyncEngine
{

public:
#if KILL_PARENT_OPT
    SignalEngine(): parentKillNotified(false) {
        parentPid = getppid();
    }
#endif

    virtual int checkEvents(int timeout);

private:
    static void StopEventLoop(void *) {
        if (EventLoop::Running)
            EventLoop::Running->stop();
    }

    static void FinalShutdownRunners(void *) {
        RunRegisteredHere(RegisteredRunner::endingShutdown);

        // XXX: this should be a Runner.
#if USE_AUTH
        /* detach the auth components (only do this on full shutdown) */
        Auth::Scheme::FreeAll();
#endif

        eventAdd("SquidTerminate", &StopEventLoop, NULL, 0, 1, false);
    }

    void doShutdown(time_t wait);
    void handleStoppedChild();

#if KILL_PARENT_OPT
    bool parentKillNotified;
    pid_t parentPid;
#endif
};

int
SignalEngine::checkEvents(int)
{
    PROF_start(SignalEngine_checkEvents);

    if (do_reconfigure)
        mainReconfigureStart();
    else if (do_rotate)
        mainRotate();
    else if (do_shutdown)
        doShutdown(do_shutdown > 0 ? (int) Config.shutdownLifetime : 0);
    if (do_handle_stopped_child)
        handleStoppedChild();
    PROF_stop(SignalEngine_checkEvents);
    return EVENT_IDLE;
}

/// Decides whether the signal-controlled action X should be delayed, canceled,
/// or executed immediately. Clears do_X (via signalVar) as needed.
static bool
AvoidSignalAction(const char *description, volatile int &signalVar)
{
    const char *avoiding = "delaying";
    const char *currentEvent = "none";
    if (shutting_down) {
        currentEvent = "shutdown";
        avoiding = "canceling";
        // do not avoid repeated shutdown signals
        // which just means the user wants to skip/abort shutdown timeouts
        if (strcmp(currentEvent, description) == 0)
            return false;
        signalVar = 0;
    }
    else if (!configured_once)
        currentEvent = "startup";
    else if (reconfiguring)
        currentEvent = "reconfiguration";
    else {
        signalVar = 0;
        return false; // do not avoid (i.e., execute immediately)
        // the caller may produce a signal-specific debugging message
    }

    debugs(1, DBG_IMPORTANT, avoiding << ' ' << description <<
           " request during " << currentEvent);
    return true;
}

void
SignalEngine::doShutdown(time_t wait)
{
    if (AvoidSignalAction("shutdown", do_shutdown))
        return;

    debugs(1, DBG_IMPORTANT, "Preparing for shutdown after " << statCounter.client_http.requests << " requests");
    debugs(1, DBG_IMPORTANT, "Waiting " << wait << " seconds for active connections to finish");

#if KILL_PARENT_OPT
    if (!IamMasterProcess() && !parentKillNotified && ShutdownSignal > 0 && parentPid > 1) {
        debugs(1, DBG_IMPORTANT, "Killing master process, pid " << parentPid);
        if (kill(parentPid, ShutdownSignal) < 0) {
            int xerrno = errno;
            debugs(1, DBG_IMPORTANT, "kill " << parentPid << ": " << xstrerr(xerrno));
        }
        parentKillNotified = true;
    }
#endif

    if (shutting_down) {
#if !KILL_PARENT_OPT
        // Already a shutdown signal has received and shutdown is in progress.
        // Shutdown as soon as possible.
        wait = 0;
#endif
    } else {
        shutting_down = 1;

        /* run the closure code which can be shared with reconfigure */
        serverConnectionsClose();

        RunRegisteredHere(RegisteredRunner::startShutdown);
    }

#if USE_WIN32_SERVICE
    WIN32_svcstatusupdate(SERVICE_STOP_PENDING, (wait + 1) * 1000);
#endif

    eventAdd("SquidShutdown", &FinalShutdownRunners, this, (double) (wait + 1), 1, false);
}

void
SignalEngine::handleStoppedChild()
{
    // no AvoidSignalAction() call: This code can run at any time because it
    // does not depend on Squid state. It does not need debugging because it
    // handles an "internal" signal, not an external/admin command.
    do_handle_stopped_child = 0;
#if !_SQUID_WINDOWS_
    PidStatus status;
    pid_t pid;

    do {
        pid = WaitForAnyPid(status, WNOHANG);

#if HAVE_SIGACTION

    } while (pid > 0);

#else

    }
    while (pid > 0 || (pid < 0 && errno == EINTR));
#endif
#endif
}

static void
usage(void)
{
    fprintf(stderr,
            "Usage: %s [-cdzCFNRVYX] [-n name] [-s | -l facility] [-f config-file] [-[au] port] [-k signal]"
#if USE_WIN32_SERVICE
            "[-ir] [-O CommandLine]"
#endif
            "\n"
            "    -h | --help       Print help message.\n"
            "    -v | --version    Print version details.\n"
            "\n"
            "       -a port   Specify HTTP port number (default: %d).\n"
            "       -d level  Write debugging to stderr also.\n"
            "       -f file   Use given config-file instead of\n"
            "                 %s\n"
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
            "       -n name   Specify service name to use for service operations\n"
            "                 default is: " APP_SHORTNAME ".\n"
#if USE_WIN32_SERVICE
            "       -r        Removes a Windows Service (see -n option).\n"
#endif
            "       -s | -l facility\n"
            "                 Enable logging to syslog.\n"
            "       -u port   Specify ICP port number (default: %d), disable with 0.\n"
            "       -z        Create missing swap directories and then exit.\n"
            "       -C        Do not catch fatal signals.\n"
            "       -D        OBSOLETE. Scheduled for removal.\n"
            "       -F        Don't serve any requests until store is rebuilt.\n"
            "       -N        Master process runs in foreground and is a worker. No kids.\n"
            "       --foreground\n"
            "                 Master process runs in foreground and creates worker kids.\n"
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
 * \param argc   Number of options received on command line
 * \param argv   List of parameters received on command line
 */
static void
mainParseOptions(int argc, char *argv[])
{
    int optIndex = 0;

    // short options
    const char *shortOpStr =
#if USE_WIN32_SERVICE
        "O:Vir"
#endif
        "CDFNRSYXa:d:f:hk:m::n:sl:u:vz?";

    // long options
    static struct option squidOptions[] = {
        {"foreground", no_argument, 0,  1 },
        {"help",       no_argument, 0, 'h'},
        {"version",    no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, shortOpStr, squidOptions, &optIndex)) != -1) {

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
             * Set global option Debug::log_stderr to the number given following the option */
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

            /** \li When it is missing or an unknown option display the usage help. */
            if (!optarg || strlen(optarg) < 1)
                usage();

            else if (!strncmp(optarg, "reconfigure", strlen(optarg)))
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
                opt_send_signal = 0;    /* SIGNULL */
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

        case 'n':
            /** \par n
             * Set global option opt_signal_service (to true).
             * Stores the additional parameter given in global service_name */
            if (optarg && *optarg != '\0') {
                const SBuf t(optarg);
                ::Parser::Tokenizer tok(t);
                const CharacterSet chr = CharacterSet::ALPHA+CharacterSet::DIGIT;
                if (!tok.prefix(service_name, chr))
                    fatalf("Expected alphanumeric service name for the -n option but got: %s", optarg);
                if (!tok.atEnd())
                    fatalf("Garbage after alphanumeric service name in the -n option value: %s", optarg);
                if (service_name.length() > 32)
                    fatalf("Service name (-n option) must be limited to 32 characters but got %u", service_name.length());
                opt_signal_service = true;
            } else {
                fatal("A service name is required for the -n option");
            }
            break;

#if USE_WIN32_SERVICE

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
            printf("Service Name: " SQUIDSBUFPH "\n", SQUIDSBUFPRINT(service_name));
            if (strlen(SQUID_BUILD_INFO))
                printf("%s\n",SQUID_BUILD_INFO);
#if USE_OPENSSL
            printf("\nThis binary uses %s. ", SSLeay_version(SSLEAY_VERSION));
            printf("For legal restrictions on distribution see https://www.openssl.org/source/license.html\n\n");
#endif
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

        case 1:
            /** \par --foreground
             * Set global option opt_foreground */
            opt_foreground = 1;
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

/// Shutdown signal handler for master process
void
master_shutdown(int sig)
{
    do_shutdown = 1;
    ShutdownSignal = sig;

#if !_SQUID_WINDOWS_
#if !HAVE_SIGACTION
    signal(sig, master_shutdown);
#endif
#endif

}

void
shut_down(int sig)
{
    do_shutdown = sig == SIGINT ? -1 : 1;
    ShutdownSignal = sig;
#if defined(SIGTTIN)
    if (SIGTTIN == sig)
        shutdown_status = 1;
#endif

#if !_SQUID_WINDOWS_
#if !HAVE_SIGACTION
    signal(sig, shut_down);
#endif
#endif
}

void
sig_child(int sig)
{
    do_handle_stopped_child = 1;

#if !_SQUID_WINDOWS_
#if !HAVE_SIGACTION
    signal(sig, sig_child);
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
        clientConnectionsClose();
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
    if (AvoidSignalAction("reconfiguration", do_reconfigure))
        return;

    debugs(1, DBG_IMPORTANT, "Reconfiguring Squid Cache (version " << version_string << ")...");
    reconfiguring = 1;

    RunRegisteredHere(RegisteredRunner::startReconfigure);

    // Initiate asynchronous closing sequence
    serverConnectionsClose();
    icpClosePorts();
#if USE_HTCP
    htcpClosePorts();
#endif
#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Shutdown();
#endif
#if USE_OPENSSL
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
    enter_suid();       /* root to read config file */

    // we may have disabled the need for PURGE
    if (Config2.onoff.enable_purge)
        Config2.onoff.enable_purge = 2;

    // parse the config returns a count of errors encountered.
    const int oldWorkers = Config.workers;
    try {
        if (parseConfigFile(ConfigFile) != 0) {
            // for now any errors are a fatal condition...
            self_destruct();
        }
    } catch (...) {
        // for now any errors are a fatal condition...
        debugs(1, DBG_CRITICAL, "FATAL: Unhandled exception parsing config file. " <<
               " Run squid -k parse and check for errors.");
        self_destruct();
    }

    if (oldWorkers != Config.workers) {
        debugs(1, DBG_CRITICAL, "WARNING: Changing 'workers' (from " <<
               oldWorkers << " to " << Config.workers <<
               ") requires a full restart. It has been ignored by reconfigure.");
        Config.workers = oldWorkers;
    }

    RunRegisteredHere(RegisteredRunner::syncConfig);

    if (IamPrimaryProcess())
        CpuAffinityCheck();
    CpuAffinityReconfigure();

    setUmask(Config.umask);
    Mem::Report();
    setEffectiveUser();
    _db_init(Debug::cache_log, Debug::debugOptions);
    ipcache_restart();      /* clear stuck entries */
    fqdncache_restart();    /* sigh, fqdncache too */
    parseEtcHosts();
    errorInitialize();      /* reload error pages */
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
    Dns::Init();
#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Init();
#endif
#if USE_OPENSSL
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

    reconfiguring = 0;
}

static void
mainRotate(void)
{
    if (AvoidSignalAction("log rotation", do_rotate))
        return;

    icmpEngine.Close();
    redirectShutdown();
#if USE_AUTH
    authenticateRotate();
#endif
    externalAclShutdown();

    _db_rotate_log();       /* cache.log */
    storeDirWriteCleanLogs(1);
    storeLogRotate();       /* store.log */
    accessLogRotate();      /* access.log */
#if ICAP_CLIENT
    icapLogRotate();               /*icap.log*/
#endif
    icmpEngine.Open();
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
    leave_suid();       /* Run as non privilegied user */
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

    int xerrno = errno;
    debugs(50, DBG_CRITICAL, "ERROR: cannot change current directory to " << dir <<
           ": " << xstrerr(xerrno));
    return false;
}

/// Hack: Have we called chroot()? This exposure is needed because some code has
/// to open the same files before and after chroot()
bool Chrooted = false;

/// set the working directory.
static void
mainSetCwd(void)
{
    if (Config.chroot_dir && !Chrooted) {
        Chrooted = true;

        if (chroot(Config.chroot_dir) != 0) {
            int xerrno = errno;
            fatalf("chroot to %s failed: %s", Config.chroot_dir, xstrerr(xerrno));
        }

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
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, "WARNING: Can't find current directory, getcwd: " << xstrerr(xerrno));
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
    squid_signal(SIGHUP, reconfigure, SA_RESTART);

    setEffectiveUser();

    if (icpPortNumOverride != 1)
        Config.Port.icp = (unsigned short) icpPortNumOverride;

    _db_init(Debug::cache_log, Debug::debugOptions);

    fd_open(fileno(debug_log), FD_LOG, Debug::cache_log);

    debugs(1, DBG_CRITICAL, "Starting Squid Cache version " << version_string << " for " << CONFIG_HOST_TYPE << "...");
    debugs(1, DBG_CRITICAL, "Service Name: " << service_name);

#if _SQUID_WINDOWS_
    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
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

    ipcache_init();

    fqdncache_init();

    parseEtcHosts();

    Dns::Init();

#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Init();
#endif

#if USE_OPENSSL
    if (Ssl::CertValidationHelper::GetInstance())
        Ssl::CertValidationHelper::GetInstance()->Init();
#endif

    redirectInit();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig);
#endif
    externalAclInit();

    httpHeaderInitModule(); /* must go before any header processing (e.g. the one in errorInitialize) */

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
        mimeInit(Config.mimeTablePathname);
        refreshInit();
#if USE_DELAY_POOLS
        DelayPools::Init();
#endif

        FwdState::initModule();
        /* register the modules in the cache manager menus */

        cbdataRegisterWithCacheManager();
        SBufStatsAction::RegisterWithCacheManager();

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

#if defined(_SQUID_LINUX_THREADS_)

    squid_signal(SIGQUIT, rotate_logs, SA_RESTART);

    squid_signal(SIGTRAP, sigusr2_handle, SA_RESTART);

#else

    squid_signal(SIGUSR1, rotate_logs, SA_RESTART);

    squid_signal(SIGUSR2, sigusr2_handle, SA_RESTART);

#endif

    squid_signal(SIGTERM, shut_down, SA_RESTART);

    squid_signal(SIGINT, shut_down, SA_RESTART);

#ifdef SIGTTIN

    squid_signal(SIGTTIN, shut_down, SA_RESTART);

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

/// describes active (i.e., thrown but not yet handled) exception
static std::ostream &
CurrentException(std::ostream &os)
{
    if (std::current_exception()) {
        try {
            throw; // re-throw to recognize the exception type
        }
        catch (const std::exception &ex) {
            os << ex.what();
        }
        catch (...) {
            os << "[unknown exception type]";
        }
    } else {
        os << "[no active exception]";
    }
    return os;
}

static void
OnTerminate()
{
    // ignore recursive calls to avoid termination loops
    static bool terminating = false;
    if (terminating)
        return;
    terminating = true;

    debugs(1, DBG_CRITICAL, "FATAL: Dying from an exception handling failure; exception: " << CurrentException);
    abort();
}

/// unsafe main routine -- may throw
int SquidMain(int argc, char **argv);
/// unsafe main routine wrapper to catch exceptions
static int SquidMainSafe(int argc, char **argv);

#if USE_WIN32_SERVICE
/* Entry point for Windows services */
extern "C" void WINAPI
SquidWinSvcMain(int argc, char **argv)
{
    SquidMainSafe(argc, argv);
}
#endif

int
main(int argc, char **argv)
{
#if USE_WIN32_SERVICE
    SetErrorMode(SEM_NOGPFAULTERRORBOX);
    if ((argc == 2) && strstr(argv[1], _WIN_SQUID_SERVICE_OPTION))
        return WIN32_StartService(argc, argv);
    else {
        WIN32_run_mode = _WIN_SQUID_RUN_MODE_INTERACTIVE;
        opt_no_daemon = 1;
    }
#endif

    return SquidMainSafe(argc, argv);
}

static int
SquidMainSafe(int argc, char **argv)
{
    (void)std::set_terminate(&OnTerminate);
    // XXX: This top-level catch works great for startup, but, during runtime,
    // it erases valuable stack info. TODO: Let stack-preserving OnTerminate()
    // handle FATAL runtime errors by splitting main code into protected
    // startup, unprotected runtime, and protected termination sections!
    try {
        return SquidMain(argc, argv);
    } catch (...) {
        debugs(1, DBG_CRITICAL, "FATAL: " << CurrentException);
    }
    return -1; // TODO: return EXIT_FAILURE instead
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

static void StartUsingConfig()
{
    RunRegisteredHere(RegisteredRunner::claimMemoryNeeds);
    RunRegisteredHere(RegisteredRunner::useConfig);
}

int
SquidMain(int argc, char **argv)
{
    ConfigureCurrentKid(argv[0]);

    Debug::parseOptions(NULL);

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

    getCurrentTime();

    squid_start = current_time;

    failure_notify = fatal_dump;

#if USE_WIN32_SERVICE

    WIN32_svcstatusupdate(SERVICE_START_PENDING, 10000);

#endif

    mainParseOptions(argc, argv);

    if (opt_foreground && opt_no_daemon) {
        debugs(1, DBG_CRITICAL, "WARNING: --foreground command-line option has no effect with -N.");
    }

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

        AnyP::UriScheme::Init();

        storeFsInit();      /* required for config parsing */

        /* TODO: call the FS::Clean() in shutdown to do Fs cleanups */
        Fs::Init();

        /* May not be needed for parsing, have not audited for such */
        DiskIOModule::SetupAllModules();

        /* Shouldn't be needed for config parsing, but have not audited for such */
        StoreFileSystem::SetupAllFs();

        /* we may want the parsing process to set this up in the future */
        Store::Init();
        Acl::Init();
        Auth::Init();      /* required for config parsing. NOP if !USE_AUTH */
        Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.

        Format::Token::Init(); // XXX: temporary. Use a runners registry of pre-parse runners instead.

        try {
            parse_err = parseConfigFile(ConfigFile);
        } catch (...) {
            // for now any errors are a fatal condition...
            debugs(1, DBG_CRITICAL, "FATAL: Unhandled exception parsing config file." <<
                   (opt_parse_cfg_only ? " Run squid -k parse and check for errors." : ""));
            parse_err = 1;
        }

        Mem::Report();

        if (opt_parse_cfg_only || parse_err > 0)
            return parse_err;
    }
    setUmask(Config.umask);

    // Master optimization: Where possible, avoid pointless daemon fork() and/or
    // pointless wait for the exclusive PID file lock. This optional/weak check
    // is not applicable to kids because they always co-exist with their master.
    if (opt_send_signal == -1 && IamMasterProcess())
        Instance::ThrowIfAlreadyRunning();

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
        return 0;
    }

    debugs(1,2, "Doing post-config initialization");
    leave_suid();
    RunRegisteredHere(RegisteredRunner::finalizeConfig);

    if (IamMasterProcess()) {
        if (InDaemonMode()) {
            watch_child(argv);
            // NOTREACHED
        } else {
            Instance::WriteOurPid();
        }
    }

    StartUsingConfig();
    enter_suid();

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

    SignalEngine signalEngine;

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
    StopUsingDebugLog();

#if USE_WIN32_SERVICE
    // WIN32_sendSignal() does not need the PID value to signal,
    // but we must exit if there is no valid PID (TODO: Why?).
    (void)Instance::Other();
    if (!opt_signal_service)
        throw TexcHere("missing -n command line switch");
    WIN32_sendSignal(opt_send_signal);
#else
    const auto pid = Instance::Other();
    if (kill(pid, opt_send_signal) &&
            /* ignore permissions if just running check */
            !(opt_send_signal == 0 && errno == EPERM)) {
        const auto savedErrno = errno;
        throw TexcHere(ToSBuf("failed to send signal ", opt_send_signal,
                              " to Squid instance with PID ", pid, ": ", xstrerr(savedErrno)));
    }
#endif
    /* signal successfully sent */
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
            PidStatus status;
            rpid = WaitForOnePid(cpid, status, 0);
        } while (rpid != cpid);
    }
}

#endif /* _SQUID_WINDOWS_ */

#if !_SQUID_WINDOWS_
static void
masterCheckAndBroadcastSignals()
{
    // if (do_reconfigure)
    //     TODO: hot-reconfiguration of the number of kids and PID file location

    if (do_shutdown)
        shutting_down = 1;

    BroadcastSignalIfAny(DebugSignal);
    BroadcastSignalIfAny(RotateSignal);
    BroadcastSignalIfAny(ReconfigureSignal);
    BroadcastSignalIfAny(ShutdownSignal);
}
#endif

static inline bool
masterSignaled()
{
    return (DebugSignal > 0 || RotateSignal > 0 || ReconfigureSignal > 0 || ShutdownSignal > 0);
}

#if !_SQUID_WINDOWS_
/// makes the caller a daemon process running in the background
static void
GoIntoBackground()
{
    pid_t pid;
    if ((pid = fork()) < 0) {
        int xerrno = errno;
        syslog(LOG_ALERT, "fork failed: %s", xstrerr(xerrno));
        // continue anyway, mimicking --foreground mode (XXX?)
    } else if (pid > 0) {
        // parent
        exit(EXIT_SUCCESS);
    }
    // child, running as a background daemon (or a failed-to-fork parent)
}
#endif /* !_SQUID_WINDOWS_ */

static void
watch_child(char *argv[])
{
#if !_SQUID_WINDOWS_
    char *prog;
    pid_t pid;
#ifdef TIOCNOTTY

    int i;
#endif

    int nullfd;

    enter_suid();

    openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

    if (!opt_foreground)
        GoIntoBackground();

    // TODO: Fails with --foreground if the calling process is process group
    //       leader, which is always (?) the case. Should probably moved to
    //       GoIntoBackground and executed only after successfully forking
    if (setsid() < 0) {
        int xerrno = errno;
        syslog(LOG_ALERT, "setsid failed: %s", xstrerr(xerrno));
    }

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

    if (nullfd < 0) {
        int xerrno = errno;
        fatalf(_PATH_DEVNULL " %s\n", xstrerr(xerrno));
    }

    dup2(nullfd, 0);

    if (Debug::log_stderr < 0) {
        dup2(nullfd, 1);
        dup2(nullfd, 2);
    }

    leave_suid();
    Instance::WriteOurPid();
    StartUsingConfig();
    enter_suid();

#if defined(_SQUID_LINUX_THREADS_)
    squid_signal(SIGQUIT, rotate_logs, 0);
    squid_signal(SIGTRAP, sigusr2_handle, 0);
#else
    squid_signal(SIGUSR1, rotate_logs, 0);
    squid_signal(SIGUSR2, sigusr2_handle, 0);
#endif

    squid_signal(SIGHUP, reconfigure, 0);

    squid_signal(SIGTERM, master_shutdown, 0);
    squid_signal(SIGINT, master_shutdown, 0);
#ifdef SIGTTIN
    squid_signal(SIGTTIN, master_shutdown, 0);
#endif

    if (Config.workers > 128) {
        syslog(LOG_ALERT, "Suspiciously high workers value: %d",
               Config.workers);
        // but we keep going in hope that user knows best
    }
    TheKids.init();

    syslog(LOG_NOTICE, "Squid Parent: will start %d kids", (int)TheKids.count());

    // keep [re]starting kids until it is time to quit
    for (;;) {
        bool mainStartScriptCalled = false;
        // start each kid that needs to be [re]started; once
        for (int i = TheKids.count() - 1; i >= 0 && !shutting_down; --i) {
            Kid& kid = TheKids.get(i);
            if (!kid.shouldRestart())
                continue;

            if (!mainStartScriptCalled) {
                mainStartScript(argv[0]);
                mainStartScriptCalled = true;
            }

            if ((pid = fork()) == 0) {
                /* child */
                openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
                prog = argv[0];
                argv[0] = const_cast<char*>(kid.name().termedBuf());
                execvp(prog, argv);
                int xerrno = errno;
                syslog(LOG_ALERT, "execvp failed: %s", xstrerr(xerrno));
            }

            kid.start(pid);
            syslog(LOG_NOTICE, "Squid Parent: %s process %d started",
                   kid.name().termedBuf(), pid);
        }

        /* parent */
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

        // If Squid received a signal while checking for dying kids (below) or
        // starting new kids (above), then do a fast check for a new dying kid
        // (WaitForAnyPid with the WNOHANG option) and continue to forward
        // signals to kids. Otherwise, wait for a kid to die or for a signal
        // to abort the blocking WaitForAnyPid() call.
        // With the WNOHANG option, we could check whether WaitForAnyPid() was
        // aborted by a dying kid or a signal, but it is not required: The
        // next do/while loop will check again for any dying kids.
        int waitFlag = 0;
        if (masterSignaled())
            waitFlag = WNOHANG;
        PidStatus status;
        pid = WaitForAnyPid(status, waitFlag);

        // check for a stopped kid
        Kid* kid = pid > 0 ? TheKids.find(pid) : NULL;
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
        } else if (pid > 0) {
            syslog(LOG_NOTICE, "Squid Parent: unknown child process %d exited", pid);
        }

        if (!TheKids.someRunning() && !TheKids.shouldRestartSome()) {
            leave_suid();
            // XXX: Master process has no main loop and, hence, should not call
            // RegisteredRunner::startShutdown which promises a loop iteration.
            RunRegisteredHere(RegisteredRunner::finishShutdown);
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

        masterCheckAndBroadcastSignals();
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
#if USE_SSL_CRTD
    Ssl::Helper::GetInstance()->Shutdown();
#endif
#if USE_OPENSSL
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
#if ICAP_CLIENT
    Adaptation::Icap::TheConfig.freeService();
#endif

    Store::Root().sync(); /* Flush pending object writes/unlinks */

    unlinkdClose();   /* after sync/flush. NOP if !USE_UNLINKD */

    storeDirWriteCleanLogs(0);
    PrintRusage();
    dumpMallocStats();
    Store::Root().sync();       /* Flush log writes */
    storeLogClose();
    accessLogClose();
    Store::Root().sync();       /* Flush log close */
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
    statFreeMemory();
    eventFreeMemory();
    mimeFreeMemory();
    errorClean();
#endif
    Store::FreeMemory();

    fdDumpOpen();

    comm_exit();

    RunRegisteredHere(RegisteredRunner::finishShutdown);

    memClean();

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

