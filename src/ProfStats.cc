
/*
 * $Id$
 *
 * DEBUG: section 81    CPU Profiling Routines
 * AUTHOR: Andres Kroonmaa
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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

#ifdef USE_XPROF_STATS

#include "CacheManager.h"
#include "event.h"
#include "SquidMath.h"
#include "Store.h"

/* Private stuff */

#define MAX_SORTLIST 200

static hrtime_t xprof_delta = 0;
static hrtime_t xprof_start_t = 0;
static hrtime_t xprof_verystart = 0;
static hrtime_t xprof_average_delta = 0;
static int xprof_events = 0;
static int xprof_inited = 0;
static xprof_stats_data Totals;

static TimersArray *xprof_stats_avg1sec = NULL;
static TimersArray *xprof_stats_avg5sec = NULL;
static TimersArray *xprof_stats_avg30sec = NULL;
static TimersArray *xprof_stats_avg1min = NULL;
static TimersArray *xprof_stats_avg5min = NULL;
static TimersArray *xprof_stats_avg30min = NULL;
static TimersArray *xprof_stats_avg1hour = NULL;
static TimersArray *xprof_stats_avg5hour = NULL;
static TimersArray *xprof_stats_avg24hour = NULL;

static xprof_stats_node *sortlist[XPROF_LAST + 2];
static void xprof_summary(StoreEntry * sentry);

static void
xprof_reset(xprof_stats_data * head)
{
    head->summ = 0;
    head->count = 0;
    head->delta = 0;
    head->best = XP_NOBEST;
    head->worst = 0;
    head->start = 0;
    head->stop = 0;
}

static void
xprof_move(xprof_stats_data * head, xprof_stats_data * hist)
{
    memcpy(hist, head, sizeof(xprof_stats_data));
}

static int
xprof_comp(xprof_stats_node ** ii, xprof_stats_node ** jj)
{
    if ((*ii)->hist.summ < (*jj)->hist.summ)
        return (1);

    if ((*ii)->hist.summ > (*jj)->hist.summ)
        return (-1);

    return (0);
}

static void
xprof_sorthist(TimersArray * xprof_list)
{
    int i;

    for (i = 0; i < XPROF_LAST; i++) {
        sortlist[i] = xprof_list[i];
    }

    qsort(&sortlist[XPROF_hash_lookup], XPROF_LAST - XPROF_hash_lookup, sizeof(xprof_stats_node *), (QS *) xprof_comp);
}

static double time_frame;

static void
xprof_show_item(StoreEntry * sentry, const char *name, xprof_stats_data * hist)
{
    storeAppendPrintf(sentry,
                      "%s\t %" PRIu64 "\t %" PRIu64 "\t %" PRIu64 "\t %" PRIu64 "\t %" PRIu64 "\t %.2f\t %6.3f\t\n",
                      name,
                      hist->count,
                      hist->summ,
                      (hist->best != XP_NOBEST ? hist->best : 0),
                      hist->count ? hist->summ / hist->count : 0,
                      hist->worst,
                      hist->count / time_frame,
                      Math::doublePercent((double) hist->summ, (double) hist->delta));
}

static void
xprof_summary_item(StoreEntry * sentry, char const *descr, TimersArray * list)
{
    int i;
    xprof_stats_node **hist;
    xprof_stats_data *show;
    xprof_reset(&Totals);
    xprof_sorthist(list);
    hist = &sortlist[0];

    show = &hist[0]->hist;

    if (!hist[0]->hist.delta)
        show = &hist[0]->accu;

    time_frame = (double) show->delta / (double) xprof_average_delta;

    storeAppendPrintf(sentry, "\n%s:", descr);

    storeAppendPrintf(sentry, " (Cumulated time: %" PRIu64 ", %.2f sec)\n",
                      show->delta,
                      time_frame
                     );

    storeAppendPrintf(sentry,
                      "Probe Name\t  Events\t cumulated time \t best case \t average \t worst case\t Rate / sec \t %% in int\n");

    for (i = 0; i < XPROF_LAST; i++) {
        if (!hist[i]->name)
            continue;

        show = &hist[i]->hist;

        if (!show->count)
            continue;

        xprof_show_item(sentry, hist[i]->name, show);

        Totals.count += show->count;

        Totals.summ += show->summ;

        Totals.best += (show->best != XP_NOBEST ? show->best : 0);

        Totals.worst += show->worst;

        Totals.delta = (show->delta > Totals.delta ? show->delta : Totals.delta);
    }

    xprof_show_item(sentry, "TOTALS", &Totals);
}

static void
xprof_average(TimersArray ** list, int secs)
{
    int i;
    TimersArray *head = xprof_Timers;
    TimersArray *hist;
    hrtime_t now;
    hrtime_t keep;
    int doavg = (xprof_events % secs);

    if (!*list)
        *list = (TimersArray *)xcalloc(XPROF_LAST, sizeof(xprof_stats_node));

    hist = *list;

    now = get_tick();

    for (i = 0; i < XPROF_LAST; i++) {
        hist[i]->name = head[i]->name;
        hist[i]->accu.summ += head[i]->accu.summ;
        hist[i]->accu.count += head[i]->accu.count;	/* accumulate multisec */

        if (!hist[i]->accu.best)
            hist[i]->accu.best = head[i]->accu.best;

        if (hist[i]->accu.best > head[i]->accu.best)
            hist[i]->accu.best = head[i]->accu.best;

        if (hist[i]->accu.worst < head[i]->accu.worst)
            hist[i]->accu.worst = head[i]->accu.worst;

        hist[i]->accu.delta += xprof_delta;

        if (!doavg) {
            /* we have X seconds accumulated */
            xprof_move(&hist[i]->accu, &hist[i]->hist);
            xprof_reset(&hist[i]->accu);

            hist[i]->accu.start = now;
        }

        /* reset 0sec counters */
        if (secs == 1) {
            keep = head[i]->accu.start;
            xprof_move(&head[i]->accu, &head[i]->hist);
            xprof_reset(&head[i]->accu);
            hist[i]->accu.delta = 0;
            head[i]->accu.start = keep;
        }
    }
}

void
xprof_summary(StoreEntry * sentry)
{
    hrtime_t now = get_tick();

    storeAppendPrintf(sentry, "CPU Profiling Statistics:\n");
    storeAppendPrintf(sentry,
                      "  (CPU times are in arbitrary units, most probably in CPU clock ticks)\n");
    storeAppendPrintf(sentry,
                      "Probe Name\t Event Count\t last Interval \t Avg Interval \t since squid start \t (since system boot) \n");
    storeAppendPrintf(sentry, "Total\t %lu\t %" PRIu64 " \t %" PRIu64 " \t %" PRIu64 " \t %" PRIu64 "\n",
                      (long unsigned) xprof_events,
                      xprof_delta,
                      xprof_average_delta,
                      now - xprof_verystart,
                      now);

    xprof_summary_item(sentry, "Last 1 sec averages", xprof_stats_avg1sec);
    xprof_summary_item(sentry, "Last 5 sec averages", xprof_stats_avg5sec);
    xprof_summary_item(sentry, "Last 30 sec averages", xprof_stats_avg30sec);
    xprof_summary_item(sentry, "Last 1 min averages", xprof_stats_avg1min);
    xprof_summary_item(sentry, "Last 5 min averages", xprof_stats_avg5min);
    xprof_summary_item(sentry, "Last 30 min averages", xprof_stats_avg30min);
    xprof_summary_item(sentry, "Last 1 hour averages", xprof_stats_avg1hour);
    xprof_summary_item(sentry, "Last 5 hour averages", xprof_stats_avg5hour);
    xprof_summary_item(sentry, "Last 24 hour averages", xprof_stats_avg24hour);
}

static inline void
xprof_chk_overhead(int samples)
{
    while (samples--) {
        PROF_start(PROF_OVERHEAD);
        PROF_stop(PROF_OVERHEAD);
    }
}

static void
xprofRegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("cpu_profile", "CPU Profiling Stats", xprof_summary, 0, 1);
}

// FIXME:
// this gets colled once per event. This doesn't seem to make much sense,
// does it?
static hrtime_t now;
static void
xprof_Init(void)
{
    if (xprof_inited)
        return;

    xprof_delta = xprof_verystart = xprof_start_t = now;

    xprof_inited = 1;

    xprofRegisterWithCacheManager(); //moved here so it's not double-init'ed
}

void
xprof_event(void *data)
{
    now = get_tick();
    xprof_Init();
    xprof_delta = now - xprof_start_t;
    xprof_start_t = now;
    xprof_events++;

    if (!xprof_average_delta)
        xprof_average_delta = xprof_delta;

    if (xprof_average_delta > (xprof_delta >> 1))
        xprof_average_delta = xprof_average_delta - (xprof_average_delta >> 8) + (xprof_delta >> 8);

    xprof_chk_overhead(2);

    xprof_average(&xprof_stats_avg24hour, 24 * 3600);

    xprof_average(&xprof_stats_avg5hour, 5 * 3600);

    xprof_average(&xprof_stats_avg1hour, 3600);

    xprof_average(&xprof_stats_avg30min, 1800);

    xprof_average(&xprof_stats_avg5min, 300);

    xprof_average(&xprof_stats_avg1min, 60);

    xprof_average(&xprof_stats_avg30sec, 30);

    xprof_average(&xprof_stats_avg5sec, 5);

    xprof_average(&xprof_stats_avg1sec, 1);

    xprof_chk_overhead(30);

    eventAdd("cpuProfiling", xprof_event, NULL, 1.0, 1);
}

#endif /* USE_XPROF_STATS */
