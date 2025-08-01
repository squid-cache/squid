/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 01    Startup and Main Loop */

#include "squid.h"
#include "AccessLogEntry.h"
//#include "acl/Acl.h"
#include "acl/forward.h"
#include "anyp/UriScheme.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "AuthReg.h"
#include "base/RunnersRegistry.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "cache_cf.h"
#include "CachePeer.h"
#include "client_db.h"
#include "client_side.h"
#include "comm.h"
#include "CommandLine.h"
#include "compat/unistd.h"
#include "ConfigParser.h"
#include "CpuAffinity.h"
#include "debug/Messages.h"
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
#include "Instance.h"
#include "ip/tools.h"
#include "ipc/Coordinator.h"
#include "ipc/Kids.h"
#include "ipc/Strand.h"
#include "ipcache.h"
#include "mime.h"
#include "neighbors.h"
#include "parser/Tokenizer.h"
#include "Parsing.h"
#include "pconn.h"
#include "PeerSelectState.h"
#include "protos.h"
#include "redirect.h"
#include "refresh.h"
#include "sbuf/Stream.h"
#include "SBufStatsAction.h"
#include "SquidConfig.h"
#include "stat.h"
#include "StatCounters.h"
#include "Store.h"
#include "store/Disks.h"
#include "store_log.h"
#include "StoreFileSystem.h"
#include "time/Engine.h"
#include "tools.h"
#include "unlinkd.h"
#include "windows_service.h"

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
static char *opt_syslog_facility = nullptr;
static int icpPortNumOverride = 1;  /* Want to detect "-u 0" */
static int configured_once = 0;
#if MALLOC_DBG
static int malloc_debug_level = 0;
#endif
static volatile int do_reconfigure = 0;
static volatile int do_rotate = 0;
static volatile int do_shutdown = 0;
static volatile int do_revive_kids = 0;
static volatile int shutdown_status = EXIT_SUCCESS;
static volatile int do_handle_stopped_child = 0;

static int RotateSignal = -1;
static int ReconfigureSignal = -1;
static int ShutdownSignal = -1;
static int ReviveKidsSignal = -1;

static void mainRotate(void);
static void mainReconfigureStart(void);
static void mainReconfigureFinish(void*);
static void mainInitialize(void);
static void usage(void);
static void mainHandleCommandLineOption(const int optId, const char *optValue);
static void sendSignal(void);
static void serverConnectionsOpen(void);
static void serverConnectionsClose(void);
static void watch_child(const CommandLine &);
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
    int checkEvents(int) override {
        Store::Root().callback();
        return EVENT_IDLE;
    };
};

class SignalEngine: public AsyncEngine
{

public:
    int checkEvents(int timeout) override;

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

        eventAdd("SquidTerminate", &StopEventLoop, nullptr, 0, 1, false);
    }

    void doShutdown(time_t wait);
    void handleStoppedChild();
};

int
SignalEngine::checkEvents(int)
{
    if (do_reconfigure)
        mainReconfigureStart();
    else if (do_rotate)
        mainRotate();
    else if (do_shutdown)
        doShutdown(do_shutdown > 0 ? (int) Config.shutdownLifetime : 0);
    if (do_handle_stopped_child)
        handleStoppedChild();
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

    debugs(1, Important(2), "Preparing for shutdown after " << statCounter.client_http.requests << " requests");
    debugs(1, Important(3), "Waiting " << wait << " seconds for active connections to finish");

    if (shutting_down) {
        // Already a shutdown signal has received and shutdown is in progress.
        // Shutdown as soon as possible.
        wait = 0;
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
            "       --kid role-ID\n"
            "                 Play a given SMP kid process role, with a given ID. Do not use\n"
            "                 this option. It is meant for the master process use only.\n"
#if USE_WIN32_SERVICE
            "       -O options\n"
            "                 Set Windows Service Command line options in Registry.\n"
#endif
            "       -R        Do not set REUSEADDR on port.\n"
            "       -S        Double-check swap during rebuild.\n"
            "       -X        Force full debugging.\n"
            "                 Add -d9 to also write full debugging to stderr.\n"
            "       -Y        Only return UDP_HIT or UDP_MISS_NOFETCH during fast reload.\n",
            APP_SHORTNAME, CACHE_HTTP_PORT, DEFAULT_CONFIG_FILE, CACHE_ICP_PORT);
    exit(EXIT_FAILURE);
}

/// CommandLine option IDs for --long options that lack a short (-x) equivalent
enum {
    // The absolute values do not matter except that the following values should
    // not be used: Values below 2 are for special getopt_long(3) use cases, and
    // values in the [33,126] range are reserved for short options (-x).
    optForeground = 2,
    optKid
};

// short options
// TODO: consider prefixing with ':' for better logging
// (distinguish missing required argument cases)
static const char *shortOpStr =
#if USE_WIN32_SERVICE
    "O:Vir"
#endif
    "CDFNRSYXa:d:f:hk:m::n:sl:u:vz?";

// long options
static struct option squidOptions[] = {
    {"foreground", no_argument, nullptr,  optForeground},
    {"kid",        required_argument, nullptr, optKid},
    {"help",       no_argument, nullptr, 'h'},
    {"version",    no_argument, nullptr, 'v'},
    {nullptr, 0, nullptr, 0}
};

// handle a command line parameter
static void
mainHandleCommandLineOption(const int optId, const char *optValue)
{
    switch (optId) {

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
        WIN32_Command_Line = xstrdup(optValue);
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
    {
        /** \par a
         * Add optional HTTP port as given following the option */
        char *port = xstrdup(optValue);
        // use a copy to avoid optValue modification
        add_http_port(port);
        xfree(port);
        break;
    }

    case 'd':
        /** \par d
         * debugs() messages with the given debugging level (and the more
         * important ones) should be written to stderr */
        Debug::ResetStderrLevel(xatoi(optValue));
        break;

    case 'f':
        /** \par f
         * Load the file given instead of the default squid.conf. */
        xfree(ConfigFile);
        ConfigFile = xstrdup(optValue);
        break;

    case 'k':
        /** \par k
         * Run the administrative action given following the option */

        /** \li When it is missing or an unknown option display the usage help. */
        if (!optValue || strlen(optValue) < 1)
            usage();

        else if (!strncmp(optValue, "reconfigure", strlen(optValue)))
            /** \li On reconfigure send SIGHUP. */
            opt_send_signal = SIGHUP;
        else if (!strncmp(optValue, "rotate", strlen(optValue)))
            /** \li On rotate send SIGQUIT or SIGUSR1. */
#if defined(_SQUID_LINUX_THREADS_)
            opt_send_signal = SIGQUIT;
#else
            opt_send_signal = SIGUSR1;
#endif

        else if (!strncmp(optValue, "debug", strlen(optValue)))
            /** \li On debug send SIGTRAP or SIGUSR2. */
#if defined(_SQUID_LINUX_THREADS_)
            opt_send_signal = SIGTRAP;
#else
            opt_send_signal = SIGUSR2;
#endif

        else if (!strncmp(optValue, "shutdown", strlen(optValue)))
            /** \li On shutdown send SIGTERM. */
            opt_send_signal = SIGTERM;
        else if (!strncmp(optValue, "interrupt", strlen(optValue)))
            /** \li On interrupt send SIGINT. */
            opt_send_signal = SIGINT;
        else if (!strncmp(optValue, "kill", strlen(optValue)))
            // XXX: In SMP mode, uncatchable SIGKILL only kills the master process
            /** \li On kill send SIGKILL. */
            opt_send_signal = SIGKILL;

#ifdef SIGTTIN

        else if (!strncmp(optValue, "restart", strlen(optValue)))
            /** \li On restart send SIGTTIN. (exit and restart by parent) */
            opt_send_signal = SIGTTIN;

#endif

        else if (!strncmp(optValue, "check", strlen(optValue)))
            /** \li On check send 0 / SIGNULL. */
            opt_send_signal = 0;    /* SIGNULL */
        else if (!strncmp(optValue, "parse", strlen(optValue)))
            /** \li On parse set global flag to re-parse the config file only. */
            opt_parse_cfg_only = 1;
        else
            usage();

        // Cannot use cache.log: use stderr for important messages (by default)
        // and stop expecting a Debug::UseCacheLog() call.
        Debug::EnsureDefaultStderrLevel(DBG_IMPORTANT);
        Debug::BanCacheLogUse();
        break;

    case 'm':
        /** \par m
         * Set global malloc_debug_level to the value given following the option.
         * if none is given it toggles the xmalloc_trace option on/off */
        if (optValue) {
#if MALLOC_DBG
            malloc_debug_level = xatoi(optValue);
#else
            fatal("Need to add -DMALLOC_DBG when compiling to use -mX option");
#endif

        }
        break;

    case 'n':
        /** \par n
         * Set global option opt_signal_service (to true).
         * Stores the additional parameter given in global service_name */
        if (optValue && *optValue != '\0') {
            const SBuf t(optValue);
            ::Parser::Tokenizer tok(t);
            const CharacterSet chr = CharacterSet::ALPHA+CharacterSet::DIGIT;
            if (!tok.prefix(service_name, chr))
                fatalf("Expected alphanumeric service name for the -n option but got: %s", optValue);
            if (!tok.atEnd())
                fatalf("Garbage after alphanumeric service name in the -n option value: %s", optValue);
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
        opt_syslog_facility = xstrdup(optValue);
        Debug::ConfigureSyslog(opt_syslog_facility);
        break;

    case 's':
        /** \par s
         * Initialize the syslog for output */
        Debug::ConfigureSyslog(opt_syslog_facility);
        break;

    case 'u':
        /** \par u
         * Store the ICP port number given in global option icpPortNumOverride
         * ensuring its a positive number. */
        icpPortNumOverride = atoi(optValue);

        if (icpPortNumOverride < 0)
            icpPortNumOverride = 0;

        break;

    case 'v':
        /** \par v
         * Display squid version and build information. Then exit. */
        printf("Squid Cache: Version %s\n",version_string);
        printf("Service Name: " SQUIDSBUFPH "\n", SQUIDSBUFPRINT(service_name));
        if (strlen(SQUID_BUILD_INFO))
            printf("%s\n",SQUID_BUILD_INFO);
#if USE_OPENSSL
        printf("\nThis binary uses %s. ", OpenSSL_version(OPENSSL_VERSION));
#if OPENSSL_VERSION_MAJOR < 3
        printf("For legal restrictions on distribution see https://www.openssl.org/source/license.html\n\n");
#endif
#endif
        printf( "configure options: %s\n", SQUID_CONFIGURE_OPTIONS);

#if USE_WIN32_SERVICE

        printf("Compiled as Windows System Service.\n");

#endif

        exit(EXIT_SUCCESS);

    /* NOTREACHED */

    case 'z':
        /** \par z
         * Request cache_dir initialization */
        opt_create_swap_dirs = 1;
        // We will use cache.log, but this command is often executed on the
        // command line, so use stderr to show important messages (by default).
        // TODO: Generalize/fix this -z-specific and sometimes faulty logic with
        // "use stderr when it is a tty [until we GoIntoBackground()]" logic.
        Debug::EnsureDefaultStderrLevel(DBG_IMPORTANT);
        break;

    case optForeground:
        /** \par --foreground
         * Set global option opt_foreground */
        opt_foreground = 1;
        break;

    case optKid:
        // already processed in ConfigureCurrentKid()
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

static void
master_revive_kids(int sig)
{
    ReviveKidsSignal = sig;
    do_revive_kids = true;

#if !_SQUID_WINDOWS_
#if !HAVE_SIGACTION
    signal(sig, master_revive_kids);
#endif
#endif
}

/// Shutdown signal handler for master process
static void
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
        shutdown_status = EXIT_FAILURE;
#endif

#if !defined(_SQUID_WINDOWS_) && !defined(HAVE_SIGACTION)
    signal(sig, shut_down);
#endif
}

void
sig_child(int sig)
{
    do_handle_stopped_child = 1;

#if !defined(_SQUID_WINDOWS_) && !defined(HAVE_SIGACTION)
    signal(sig, sig_child);
#else
    (void)sig;
#endif
}

static void
serverConnectionsOpen(void)
{
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
        Acl::Node::Initialize();
        peerSelectInit();
    }
}

static void
serverConnectionsClose(void)
{
    assert(shutting_down || reconfiguring);

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
#if USE_OPENSSL
    Ssl::TheGlobalContextStorage().reconfigureStart();
#endif
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
    Security::CloseLogs();

    eventAdd("mainReconfigureFinish", &mainReconfigureFinish, nullptr, 0, 1,
             false);
}

/// error message to log when Configuration::Parse() fails
static SBuf
ConfigurationFailureMessage()
{
    SBufStream out;
    out << (reconfiguring ? "re" : "");
    out << "configuration failure: " << CurrentException;
    if (!opt_parse_cfg_only)
        out << Debug::Extra << "advice: Run 'squid -k parse' and check for ERRORs.";
    return out.buf();
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

    const int oldWorkers = Config.workers;

    try {
        Configuration::Parse();
    } catch (...) {
        // for now any errors are a fatal condition...
        fatal(ConfigurationFailureMessage().c_str());
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
    setEffectiveUser();
    Debug::UseCacheLog();
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

    Security::OpenLogs();
#if ICAP_CLIENT
    icapLogOpen();
#endif
    storeLogOpen();
    Dns::Init();
#if USE_SSL_CRTD
    Ssl::Helper::Reconfigure();
#endif
#if USE_OPENSSL
    Ssl::CertValidationHelper::Reconfigure();
#endif

    redirectReconfigure();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig.schemes);
#endif
    externalAclInit();

    serverConnectionsOpen();

    neighbors_init();

    storeDirOpenSwapLogs();

    mimeInit(Config.mimeTablePathname);

    if (unlinkdNeeded())
        unlinkdInit();

#if USE_DELAY_POOLS
    Config.ClientDelay.finalize();
#endif

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
    Security::RotateLogs();
#if ICAP_CLIENT
    icapLogRotate();               /*icap.log*/
#endif
    icmpEngine.Open();
    redirectInit();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig.schemes);
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
            debugs(0, Important(4), "Set Current Directory to " << Config.coredump_dir);
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

    debugs(1, DBG_CRITICAL, "Starting Squid Cache version " << version_string << " for " << CONFIG_HOST_TYPE << "...");
    debugs(1, Critical(5), "Service Name: " << service_name);

#if _SQUID_WINDOWS_
    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        debugs(1, DBG_CRITICAL, "Service command line is: " << WIN32_Service_Command_Line);
    } else
        debugs(1, DBG_CRITICAL, "Running on " << WIN32_OS_string);
#endif

    debugs(1, Important(6), "Process ID " << getpid());

    debugs(1, Important(7), "Process Roles:" << ProcessRoles());

    setSystemLimits();
    debugs(1, Important(8), "With " << Squid_MaxFD << " file descriptors available");

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
    Ssl::Helper::Init();
#endif

#if USE_OPENSSL
    Ssl::CertValidationHelper::Init();
#endif

    redirectInit();
#if USE_AUTH
    authenticateInit(&Auth::TheConfig.schemes);
#endif
    externalAclInit();

    httpHeaderInitModule(); /* must go before any header processing (e.g. the one in errorInitialize) */

    errorInitialize();

    accessLogInit();

    Security::OpenLogs();

#if ICAP_CLIENT
    icapLogOpen();
#endif

#if SQUID_SNMP

    snmpInit();

#endif
#if MALLOC_DBG

    malloc_debug(0, malloc_debug_level);

#endif

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
    SBufStatsAction::RegisterWithCacheManager();

    AsyncJob::RegisterWithCacheManager();

    /* These use separate calls so that the comm loops can eventually
     * coexist.
     */

    eventInit();

    // TODO: pconn is a good candidate for new-style registration
    // PconnModule::GetInstance()->registerWithCacheManager();
    // moved to PconnModule::PconnModule()

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

#if USE_DELAY_POOLS
    Config.ClientDelay.finalize();
#endif

    eventAdd("storeMaintain", Store::Maintain, nullptr, 1.0, 1);

    eventAdd("ipcache_purgelru", ipcache_purgelru, nullptr, 10.0, 1);

    eventAdd("fqdncache_purgelru", fqdncache_purgelru, nullptr, 15.0, 1);

    eventAdd("memPoolCleanIdlePools", Mem::CleanIdlePools, nullptr, 15.0, 1);

    configured_once = 1;
}

static void
OnTerminate()
{
    // ignore recursive calls to avoid termination loops
    static bool terminating = false;
    if (terminating)
        return;
    terminating = true;

    debugs(1, DBG_CRITICAL, "FATAL: Dying after an undetermined failure" << CurrentExceptionExtra);

    Debug::PrepareToDie();
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
    return EXIT_FAILURE;
}

/// computes name and ID for the current kid process
static void
ConfigureCurrentKid(const CommandLine &cmdLine)
{
    const char *kidParams = nullptr;
    if (cmdLine.hasOption(optKid, &kidParams)) {
        SBuf processName(kidParams);
        SBuf kidId;
        Parser::Tokenizer tok(processName);
        tok.suffix(kidId, CharacterSet::DIGIT);
        KidIdentifier = xatoi(kidId.c_str());
        tok.skipSuffix(SBuf("-"));
        TheKidName = tok.remaining();
        if (TheKidName.cmp("squid-coord") == 0)
            TheProcessKind = pkCoordinator;
        else if (TheKidName.cmp("squid") == 0)
            TheProcessKind = pkWorker;
        else if (TheKidName.cmp("squid-disk") == 0)
            TheProcessKind = pkDisker;
        else
            TheProcessKind = pkOther; // including coordinator
    } else {
        TheKidName.assign(APP_SHORTNAME);
        KidIdentifier = 0;
    }
    Debug::NameThisKid(KidIdentifier);
}

/// Start directing debugs() messages to the configured cache.log.
static void
ConfigureDebugging()
{
    if (opt_no_daemon) {
        fd_open(0, FD_LOG, "stdin");
        fd_open(1, FD_LOG, "stdout");
        fd_open(2, FD_LOG, "stderr");
    }
    // we should not create cache.log outside chroot environment, if any
    // XXX: With Config.chroot_dir set, SMP master process calls Debug::BanCacheLogUse().
    if (!Config.chroot_dir || Chrooted)
        Debug::UseCacheLog();
    else
        Debug::BanCacheLogUse();
}

static void
RunConfigUsers()
{
    RunRegisteredHere(RegisteredRunner::claimMemoryNeeds);
    RunRegisteredHere(RegisteredRunner::useConfig);
}

static void
StartUsingConfig()
{
    setMaxFD();
    fde::Init();
    const auto skipCwdAdjusting = IamMasterProcess() && InDaemonMode();
    if (skipCwdAdjusting) {
        ConfigureDebugging();
        RunConfigUsers();
    } else if (Config.chroot_dir) {
        RunConfigUsers();
        enter_suid();
        // TODO: don't we need to RunConfigUsers() in the configured
        // chroot environment?
        mainSetCwd();
        leave_suid();
        ConfigureDebugging();
    } else {
        ConfigureDebugging();
        RunConfigUsers();
        enter_suid();
        // TODO: since RunConfigUsers() may use a relative path, we
        // need to change the process root first
        mainSetCwd();
        leave_suid();
    }
}

/// register all known modules for handling future RegisteredRunner events
static void
RegisterModules()
{
    // These registration calls do not represent a RegisteredRunner "event". The
    // modules registered here should be initialized later, during those events.

    // RegisteredRunner event handlers should not depend on handler call order
    // and, hence, should not depend on the registration call order below.

    CallRunnerRegistrator(CarpRr);
    CallRunnerRegistrator(ClientDbRr);
    CallRunnerRegistrator(CollapsedForwardingRr);
    CallRunnerRegistrator(MemStoreRr);
    CallRunnerRegistrator(PeerPoolMgrsRr);
    CallRunnerRegistrator(PeerSourceHashRr);
    CallRunnerRegistrator(SharedMemPagesRr);
    CallRunnerRegistrator(SharedSessionCacheRr);
    CallRunnerRegistrator(TransientsRr);
    CallRunnerRegistratorIn(Dns, ConfigRr);

#if HAVE_DISKIO_MODULE_IPCIO
    CallRunnerRegistrator(IpcIoRr);
#endif

#if HAVE_AUTH_MODULE_NTLM
    CallRunnerRegistrator(NtlmAuthRr);
#endif

#if USE_AUTH
    CallRunnerRegistrator(PeerUserHashRr);
#endif

#if USE_OPENSSL
    CallRunnerRegistrator(sslBumpCfgRr);
#endif

#if HAVE_FS_ROCK
    CallRunnerRegistratorIn(Rock, SwapDirRr);
#endif

#if USE_WCCP
    CallRunnerRegistrator(WccpRr);
#endif
#if USE_WCCPv2
    CallRunnerRegistrator(Wccp2Rr);
#endif
}

int
SquidMain(int argc, char **argv)
{
    // We must register all modules before the first RunRegisteredHere() call.
    // We do it ASAP/here so that we do not need to move this code when we add
    // earlier hooks to the RegisteredRunner API.
    RegisterModules();

    const CommandLine cmdLine(argc, argv, shortOpStr, squidOptions);

    ConfigureCurrentKid(cmdLine);

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
    AnyP::UriScheme::Init(); // needs to be before arg parsing, bug 5337

    cmdLine.forEachOption(mainHandleCommandLineOption);

    Debug::SettleStderr();
    Debug::SettleSyslog();

    if (opt_foreground && opt_no_daemon) {
        debugs(1, DBG_CRITICAL, "WARNING: --foreground command-line option has no effect with -N.");
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
        if (!ConfigFile)
            ConfigFile = xstrdup(DEFAULT_CONFIG_FILE);

        assert(!configured_once);

        Mem::Init();

        storeFsInit();      /* required for config parsing */

        Fs::Init();

        /* May not be needed for parsing, have not audited for such */
        DiskIOModule::SetupAllModules();

        /* we may want the parsing process to set this up in the future */
        Acl::Init();
        Auth::Init();      /* required for config parsing. NOP if !USE_AUTH */
        Ip::ProbeTransport(); // determine IPv4 or IPv6 capabilities before parsing.

        Format::Token::Init(); // XXX: temporary. Use a runners registry of pre-parse runners instead.

        RunRegisteredHere(RegisteredRunner::bootstrapConfig);

        try {
            Configuration::Parse();
        } catch (...) {
            auto msg = ConfigurationFailureMessage();
            if (opt_parse_cfg_only) {
                debugs(3, DBG_CRITICAL, "FATAL: " << msg);
                return EXIT_FAILURE;
            } else {
                fatal(msg.c_str());
                return EXIT_FAILURE; // unreachable
            }
        }

        if (opt_parse_cfg_only)
            return EXIT_SUCCESS;
    }
    setUmask(Config.umask);

    // Master optimization: Where possible, avoid pointless daemon fork() and/or
    // pointless wait for the exclusive PID file lock. This optional/weak check
    // is not applicable to kids because they always co-exist with their master.
    if (opt_send_signal == -1 && IamMasterProcess())
        Instance::ThrowIfAlreadyRunning();

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
            watch_child(cmdLine);
            // NOTREACHED
        } else {
            Instance::WriteOurPid();
        }
    }

    StartUsingConfig();
    enter_suid();

    if (opt_create_swap_dirs) {
        setEffectiveUser();
        debugs(0, DBG_CRITICAL, "Creating missing swap directories");
        Store::Root().create();

        return 0;
    }

    if (IamPrimaryProcess())
        CpuAffinityCheck();
    CpuAffinityInit();

    /* init comm module */
    comm_init();

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
    Time::Engine time_engine;

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
        execl(script, squid_start_script, (char *)nullptr);
        _exit(-1);
    } else {
        do {
            PidStatus status;
            rpid = WaitForOnePid(cpid, status, 0);
        } while (rpid != cpid);
    }
}

/// Initiates shutdown sequence. Shutdown ends when the last running kids stops.
static void
masterShutdownStart()
{
    if (AvoidSignalAction("shutdown", do_shutdown))
        return;
    debugs(1, 2, "received shutdown command");
    shutting_down = 1;
}

/// Initiates reconfiguration sequence. See also: masterReconfigureFinish().
static void
masterReconfigureStart()
{
    if (AvoidSignalAction("reconfiguration", do_reconfigure))
        return;
    debugs(1, 2, "received reconfiguration command");
    reconfiguring = 1;
    TheKids.forgetAllFailures();
    // TODO: hot-reconfiguration of the number of kids, kids revival delay,
    // PID file location, etc.
}

/// Ends reconfiguration sequence started by masterReconfigureStart().
static void
masterReconfigureFinish()
{
    reconfiguring = 0;
}

/// Reacts to the kid revival alarm.
static void
masterReviveKids()
{
    if (AvoidSignalAction("kids revival", do_revive_kids))
        return;
    debugs(1, 2, "woke up after ~" << Config.hopelessKidRevivalDelay << "s");
    // nothing to do here -- actual revival happens elsewhere in the main loop
    // the alarm was needed just to wake us up so that we do a loop iteration
}

static void
masterCheckAndBroadcastSignals()
{
    if (do_shutdown)
        masterShutdownStart();
    if (do_reconfigure)
        masterReconfigureStart();
    if (do_revive_kids)
        masterReviveKids();

    // emulate multi-step reconfiguration assumed by AvoidSignalAction()
    if (reconfiguring)
        masterReconfigureFinish();

    BroadcastSignalIfAny(DebugSignal);
    BroadcastSignalIfAny(RotateSignal);
    BroadcastSignalIfAny(ReconfigureSignal);
    BroadcastSignalIfAny(ShutdownSignal);
    ReviveKidsSignal = -1; // alarms are not broadcasted
}

/// Maintains the following invariant: An alarm should be scheduled when and
/// only when there are hopeless kid(s) that cannot be immediately revived.
static void
masterMaintainKidRevivalSchedule()
{
    const auto nextCheckDelay = TheKids.forgetOldFailures();
    assert(nextCheckDelay >= 0);
    (void)alarm(static_cast<unsigned int>(nextCheckDelay)); // resets or cancels
    if (nextCheckDelay)
        debugs(1, 2, "will recheck hopeless kids in " << nextCheckDelay << " seconds");
}

static inline bool
masterSignaled()
{
    return (DebugSignal > 0 || RotateSignal > 0 || ReconfigureSignal > 0 ||
            ShutdownSignal > 0 || ReviveKidsSignal > 0);
}

/// makes the caller a daemon process running in the background
static void
GoIntoBackground()
{
    pid_t pid;
    if ((pid = fork()) < 0) {
        int xerrno = errno;
        throw TexcHere(ToSBuf("failed to fork(2) the master process: ", xstrerr(xerrno)));
    } else if (pid > 0) {
        // parent
        // The fork() effectively duped any saved debugs() messages. For
        // simplicity sake, let the child process deal with them.
        Debug::ForgetSaved();
        exit(EXIT_SUCCESS);
    }
    // child, running as a background daemon
    Must(setsid() > 0); // ought to succeed after fork()
}

static void
masterExit()
{
    if (TheKids.someSignaled(SIGINT) || TheKids.someSignaled(SIGTERM)) {
        syslog(LOG_ALERT, "Exiting due to unexpected forced shutdown");
        exit(EXIT_FAILURE);
    }

    if (TheKids.allHopeless()) {
        syslog(LOG_ALERT, "Exiting due to repeated, frequent failures");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}

#endif /* !_SQUID_WINDOWS_ */

static void
watch_child(const CommandLine &masterCommand)
{
#if !_SQUID_WINDOWS_
    pid_t pid;
#ifdef TIOCNOTTY

#endif

    // TODO: zero values are not supported because they result in
    // misconfigured SMP Squid instances running forever, endlessly
    // restarting each dying kid.
    if (Config.hopelessKidRevivalDelay <= 0)
        throw TexcHere("hopeless_kid_revival_delay must be positive");

    enter_suid();

    openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);

    if (!opt_foreground)
        GoIntoBackground();

    closelog();

#ifdef TIOCNOTTY

    if ((const auto i = xopen("/dev/tty", O_RDWR | O_TEXT)) >= 0) {
        ioctl(i, TIOCNOTTY, nullptr);
        close(i);
    }

#endif

    /*
     * RBCOLLINS - if cygwin stackdumps when squid is run without
     * -N, check the cygwin1.dll version, it needs to be AT LEAST
     * 1.1.3.  execvp had a bit overflow error in a loop..
     */
    /* Connect stdio to /dev/null in daemon mode */
    const auto nullfd = xopen(_PATH_DEVNULL, O_RDWR | O_TEXT);

    if (nullfd < 0) {
        int xerrno = errno;
        fatalf(_PATH_DEVNULL " %s\n", xstrerr(xerrno));
    }

    dup2(nullfd, 0);

    if (!Debug::StderrEnabled()) {
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
    squid_signal(SIGALRM, master_revive_kids, 0);
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

    configured_once = 1;

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
                mainStartScript(masterCommand.arg0());
                mainStartScriptCalled = true;
            }

            // These are only needed by the forked child below, but let's keep
            // them out of that "no man's land" between fork() and execvp().
            auto kidCommand = masterCommand;
            kidCommand.resetArg0(kid.processName().c_str());
            assert(!kidCommand.hasOption(optKid));
            kidCommand.pushFrontOption("--kid", kid.gist().c_str());

            if ((pid = fork()) == 0) {
                /* child */
                openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_LOCAL4);
                (void)execvp(masterCommand.arg0(), kidCommand.argv());
                int xerrno = errno;
                syslog(LOG_ALERT, "execvp failed: %s", xstrerr(xerrno));
            }

            kid.start(pid);
            syslog(LOG_NOTICE, "Squid Parent: %s process %d started",
                   kid.processName().c_str(), pid);
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
        getCurrentTime();

        // check for a stopped kid
        if (Kid *kid = pid > 0 ? TheKids.find(pid) : nullptr)
            kid->stop(status);
        else if (pid > 0)
            syslog(LOG_NOTICE, "Squid Parent: unknown child process %d exited", pid);

        masterCheckAndBroadcastSignals();
        masterMaintainKidRevivalSchedule();

        if (!TheKids.someRunning() && !TheKids.shouldRestartSome()) {
            leave_suid();
            // XXX: Master process has no main loop and, hence, should not call
            // RegisteredRunner::startShutdown which promises a loop iteration.
            RunRegisteredHere(RegisteredRunner::finishShutdown);
            enter_suid();
            masterExit();
        }
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

    debugs(1, Important(9), "Shutting down...");
#if USE_SSL_CRTD
    Ssl::Helper::Shutdown();
#endif
#if USE_OPENSSL
    Ssl::CertValidationHelper::Shutdown();
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
    releaseServerSockets();
    commCloseAllSockets();

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
    DiskIOModule::FreeAllModules();

    fdDumpOpen();

    comm_exit();

    RunRegisteredHere(RegisteredRunner::finishShutdown);

    memClean();

    debugs(1, Important(10), "Squid Cache (Version " << version_string << "): Exiting normally.");

    exit(shutdown_status);
}

