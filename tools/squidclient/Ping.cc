/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SquidTime.h"
#include "tools/squidclient/Parameters.h"
#include "tools/squidclient/Ping.h"

#include <climits>
#include <csignal>
#include <iostream>

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

namespace Ping
{
Ping::TheConfig Config;

/// measurements collected by the squidclient ping mode logics
class pingStats_
{
public:
    pingStats_() {memset(this, 0, sizeof(pingStats_));}

    long counted;  ///< number of transactions which have so far been measured
    long pMin;     ///< shortest transaction time seen
    long pMax;     ///< longest transaction time seen
    long sum;      ///< total time so far spent waiting on transactions

} stats;

} // namespace Ping

/**
 * Signal interrupt handler for squidclient ping.
 * Displays final statistics and disables further pings.
 */
static void
catchSignal(int sig)
{
    Ping::DisplayStats();
    Ping::Config.enable = false;
    std::cerr << "SIGNAL " << sig << " Interrupted." << std::endl;
}

uint32_t
Ping::Init()
{
    if (Ping::Config.enable) {
#if HAVE_SIGACTION
        struct sigaction sa, osa;
        if (sigaction(SIGINT, NULL, &osa) == 0 && osa.sa_handler == SIG_DFL) {
            sa.sa_handler = catchSignal;
            sa.sa_flags = 0;
            sigemptyset(&sa.sa_mask);
            (void) sigaction(SIGINT, &sa, NULL);
        }
#else
        void (*osig) (int);
        if ((osig = signal(SIGINT, catchSignal)) != SIG_DFL)
            (void) signal(SIGINT, osig);
#endif
        return Ping::Config.count;
    }

    return 1;
}

static struct timeval tv1, tv2;

void
Ping::TimerStart()
{
    if (!Ping::Config.enable)
        return;

#if GETTIMEOFDAY_NO_TZP
    (void)gettimeofday(&tv1);
#else
    (void)gettimeofday(&tv1, NULL);
#endif
}

void
Ping::TimerStop(size_t fsize)
{
    if (!Ping::Config.enable)
        return;

    struct tm *tmp;
    time_t t2s;
    long elapsed_msec;

#if GETTIMEOFDAY_NO_TZP
    (void)gettimeofday(&tv2);
#else
    (void)gettimeofday(&tv2, NULL);
#endif

    elapsed_msec = tvSubMsec(tv1, tv2);
    t2s = tv2.tv_sec;
    tmp = localtime(&t2s);
    char tbuf[4096];
    snprintf(tbuf, sizeof(tbuf)-1, "%d-%02d-%02d %02d:%02d:%02d [%ld]: %ld.%03ld secs, %f KB/s",
             tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
             tmp->tm_hour, tmp->tm_min, tmp->tm_sec, stats.counted + 1,
             elapsed_msec / 1000, elapsed_msec % 1000,
             elapsed_msec ? (double) fsize / elapsed_msec : -1.0);
    std::cerr << tbuf << std::endl;

    if (!stats.counted || elapsed_msec < stats.pMin)
        stats.pMin = elapsed_msec;

    if (!stats.counted || elapsed_msec > stats.pMax)
        stats.pMax = elapsed_msec;

    stats.sum += elapsed_msec;

    ++stats.counted;

    /* Delay until next "ping.interval" boundary */
    if (!LoopDone(stats.counted) && elapsed_msec < Ping::Config.interval) {

        struct timeval tvs;
        long msec_left = Ping::Config.interval - elapsed_msec;

        tvs.tv_sec = msec_left / 1000;
        tvs.tv_usec = (msec_left % 1000) * 1000;
        select(0, NULL, NULL, NULL, &tvs);
    }
}

void
Ping::DisplayStats()
{
    if (Ping::Config.enable && stats.counted) {
        long mean = stats.sum / stats.counted;
        std::cerr << std::endl
                  << stats.counted << " requests, round-trip (secs) min/avg/max = "
                  << (stats.pMin/1000) << "." << (stats.pMin%1000)
                  << "/" << (mean/1000) << "." << (mean%1000)
                  << "/" << (stats.pMax/1000) << "." << (stats.pMax%1000)
                  << std::endl;
    }
}

void
Ping::TheConfig::usage()
{
    std::cerr << "Ping Mode" << std::endl
              << "  --ping [options]  Enable ping mode." << std::endl
              << std::endl
              << "  options:" << std::endl
              << "    -g count        Ping iteration count (default, loop until interrupted)." << std::endl
              << "    -I interval     Ping interval in seconds (default 1 second)." << std::endl
              << std::endl;
}

bool
Ping::TheConfig::parseCommandOpts(int argc, char *argv[], int c, int &optIndex)
{
    // to get here --ping was seen
    enable = true;
    count = 0;           // default is infinite loop
    interval = 1 * 1000; // default is 1s intervals

    const char *shortOpStr = "g:I:?";

    // options for controlling squidclient ping mode
    static struct option pingOptions[] = {
        {"count",    no_argument, 0, 'g'},
        {"interval", no_argument, 0, 'I'},
        {0, 0, 0, 0}
    };

    int saved_opterr = opterr;
    opterr = 0; // suppress errors from getopt
    while ((c = getopt_long(argc, argv, shortOpStr, pingOptions, &optIndex)) != -1) {
        switch (c) {
        case 'g':
            if (optarg)
                count = atoi(optarg);
            else {
                std::cerr << "ERROR: -g ping count missing parameter." << std::endl;
                usage();
            }
            break;

        case 'I':
            if (!optarg) {
                std::cerr << "ERROR: -I ping interval missing parameter." << std::endl;
                usage();
            } else if ((interval = atoi(optarg) * 1000) <= 0) {
                std::cerr << "ERROR: -I ping interval out of range (0-" << (INT_MAX/1000) << ")." << std::endl;
                usage();
            }
            break;

        default:
            // rewind and let the caller handle unknown options
            --optind;
            opterr = saved_opterr;
            return true;
        }
    }

    opterr = saved_opterr;
    return false;
}

