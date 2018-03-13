/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "cache_cf.h"
#include "CommandLine.h"
#include "fatal.h"
#include "globals.h"
#include "parser/Tokenizer.h"
#include "tools.h"

#if USE_OPENSSL
#include "ssl/context_storage.h"
#endif

#include <algorithm>
#include <getopt.h>

static char *opt_syslog_facility = NULL;

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
            "       --kid\n"
            "                 A kid name passed to a worker Squid process.\n"
            "                 Warning: do not use it directly since it is an internal option.\n"
#if USE_WIN32_SERVICE
            "       -O options\n"
            "                 Set Windows Service Command line options in Registry.\n"
#endif
            "       -R        Do not set REUSEADDR on port.\n"
            "       -S        Double-check swap during rebuild.\n"
            "       -X        Force full debugging.\n"
            "       -Y        Only return UDP_HIT or UDP_MISS_NOFETCH during fast reload.\n",
            APP_SHORTNAME, CACHE_HTTP_PORT, DefaultConfigFile, CACHE_ICP_PORT);
    exit(EXIT_FAILURE);
}

CommandLine::CommandLine(const int anArgc, char *anArgv[])
    : execFile_(anArgv[0])
{
    parse(anArgc, anArgv);
}

void
CommandLine::parse(int anArgc, char *anArgv[])
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
        {"foreground", no_argument, 0,  ForegroundCode},
        {"kid",        required_argument, 0, KidCode},
        {"help",       no_argument, 0, 'h'},
        {"version",    no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int c;

    while ((c = getopt_long(anArgc, anArgv, shortOpStr, squidOptions, &optIndex)) != -1) {
        if (c == '?' || c == 'h') {
            usage();
            // unreacheable
            break;
        }
        options.push_back(std::make_pair(c, optarg ? SBuf(optarg) : SBuf()));
    }

    // reserve space for --kid option (with argument) and nil termination pointer
    argv_.clear();
    argv_.reserve(anArgc + 3);
    for (int i = 0; i < anArgc; ++i)
        argv_.push_back(anArgv[i]);
}

const char **
CommandLine::argv(const char *argv0, const char *kid)
{
    argv_[0] = argv0;

    auto kidPos = std::find_if(argv_.begin(), argv_.end(), [](const char *opt)
            { return strcmp(opt, "--kid") == 0; });
    // not expected to happen because kids do not create kids
    if (kidPos != argv_.end()) {
        assert(++kidPos != argv_.end());
        *kidPos = xstrdup(kid);
    } else {
        argv_.push_back("--kid");
        argv_.push_back(xstrdup(kid));
    }
    argv_.push_back(nullptr);
    return &argv_[0];
}

SBuf
CommandLine::kidName() const
{
    auto kidOpt = std::find_if(options.begin(), options.end(), [](const OptionsPair &p)
             { return p.first == KidCode; });
    if (kidOpt == options.end())
        return SBuf();
    return kidOpt->second;
}

void
CommandLine::processOptions()
{
    std::for_each(options.begin(), options.end(), [this](OptionsPair &opt)
            { processOption(opt.first, opt.second.isEmpty() ? nullptr : opt.second.c_str()); });
}

// apply a single option
void
CommandLine::processOption(const char optCode, const char *optArg)
{
    // XXX: use optArg instead
    optarg = const_cast<char *>(optArg);
    switch (optCode) {

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
            {
                /** \par a
                 * Add optional HTTP port as given following the option */
                char *portOpt = xstrdup(optarg);
                add_http_port(portOpt);
                xfree(portOpt);
                break;
            }

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
            printf("Squid Cache: Version %s\n",version_string);
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

            exit(EXIT_SUCCESS);

        /* NOTREACHED */

        case 'z':
            /** \par z
             * Set global option Debug::log_stderr and opt_create_swap_dirs */
            Debug::log_stderr = 1;
            opt_create_swap_dirs = 1;
            break;

        case ForegroundCode:
            /** \par --foreground
             * Set global option opt_foreground */
            opt_foreground = 1;
            break;

        case KidCode:
            // \par --kid
            // expected to be already applied in SquidMain()
            break;

        default:
            fatalf("Unexpected option with code %d", optCode);
            break;
    }
}

