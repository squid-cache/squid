
/*
 * $Id: Profiler.c,v 1.5 2004/12/21 17:28:28 robertc Exp $
 *
 * DEBUG: section 81     CPU Profiling Routines
 * AUTHOR: Andres Kroonmaa, Sep.2000
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

/*
 * CPU Profiling implementation.
 * 
 *  This library implements the Probes needed to gather stats.
 *  See src/ProfStats.c which implements historical recording and
 *  presentation in CacheMgr.cgi.
 * 
 *  For timing we prefer on-CPU ops that retrieve cpu ticks counter.
 *  For Intel, this is "rdtsc", which is 64-bit counter that virtually
 *  never wraps. For alpha, this is "rpcc" which is 32-bit counter and
 *  wraps every few seconds. Currently, no handling of wrapping counters
 *  is implemented. Other CPU's are also not covered. Potentially all
 *  modern CPU's has similar counters.
 * 
 * Usage.
 *  Insert macro PROF_state(probename) in strategic places in code.
 *    PROF_start(probename);
 *     ...  section of code measured ...
 *    PROF_stop(probename);
 * 
 *   probename must be added to profiling.h into xprof_type enum list
 *   with prepended "XPROF_" string.
 *
 * Description.
 *  PROF gathers stats per probename into structures. It indexes these
 *  structures by enum type index in an array.
 * 
 *  PROF records best, best, average and worst values for delta time,
 *  also, if UNACCED is defined, it measures "empty" time during which
 *  no probes are in measuring state. This allows to see time "unaccounted"
 *  for. If OVERHEAD is defined, additional calculations are made at every
 *  probe to measure approximate overhead of the probe code itself.
 * 
 *  Probe data is stored in linked-list, so the more probes you define,
 *  the more overhead is added to find the deepest nested probe. To reduce
 *  average overhead, linked list is manipulated each time PR_start is
 *  called, so that probe just started is moved 1 position up in linkedlist.
 *  This way frequently used probes are moved closer to the head of list,
 *  reducing average overhead.
 *  Note that all overhead is on the scale of one hundred of CPU clock
 *  ticks, which on the scale of submicroseconds. Yet, to optimise really
 *  fast and frequent sections of code, we want to reduce this overhead
 *  to absolute minimum possible.
 * 
 *  For actual measurements, probe overhead cancels out mostly. Still,
 *  do not take the measured times as facts, they should be viewed in
 *  relative comparison to overall CPU time and on the same platform.
 * 
 *  Every 1 second, Event within squid is called that parses gathered
 *  statistics of every probe, and accumulates that into historical
 *  structures for last 1,5,30 secs, 1,5,30 mins, and 1,5 and 24 hours.
 *  Each second active probe stats are reset, and only historical data
 *  is presented in cachemgr output.
 * 
 * Reading stats.
 *  "Worst case" may be misleading. Anything can happen at any section
 *  of code that could delay reaching to probe stop. For eg. system may
 *  need to service interrupt routine, task switch could occur, or page
 *  fault needs to be handled. In this sense, this is quite meaningless
 *  metric. "Best case" shows fastest completion of probe section, and
 *  is also somewhat useless, unless you know that amount of work is
 *  constant. Best metric to watch is "average time" and total cumulated
 *  time in given timeframe, which really show percentage of time spent
 *  in given section of code, and its average completion time. This data
 *  could be used to detect bottlenecks withing squid and optimise them.
 * 
 *  TOTALS are quite off reality. Its there just to summarise cumulative
 *  times and percent column. Percent values over 100% shows that there
 *  have been some probes nested into each other.
 * 
 */

#include "profiling.h"

#ifdef USE_XPROF_STATS


#if HAVE_GNUMALLLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Exported Data */
TimersArray *xprof_Timers = NULL;
int xprof_nesting = 0;

/* Private stuff */

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
static __inline void
#else
static inline void
#endif
xprof_update(xprof_stats_data * head)
{
    head->delta = head->stop - head->start;
    if (head->delta < head->best)
	head->best = head->delta;
    if (head->worst < head->delta)
	head->worst = head->delta;
    head->summ += head->delta;
    head->count++;
}

static xprof_stats_data *xp_UNACCOUNTED;
static int xprof_inited = 0;

static void
xprof_InitLib(void)
{
    if (xprof_inited)
	return;

    xprof_Timers = calloc(XPROF_LAST + 2, sizeof(xprof_stats_node));

    xprof_Timers[XPROF_PROF_UNACCOUNTED]->name = "PROF_UNACCOUNTED";
    xprof_Timers[XPROF_PROF_UNACCOUNTED]->accu.start = get_tick();
    xp_UNACCOUNTED = &xprof_Timers[XPROF_PROF_UNACCOUNTED]->accu;
    xprof_inited = 1;
}

void
xprof_start(xprof_type type, const char *timer)
{
    if (!xprof_inited)
	xprof_InitLib();

    xprof_Timers[type]->accu.start = get_tick();
    xprof_Timers[type]->name = timer;

    if (xprof_nesting++)
	return;
    xp_UNACCOUNTED->stop = xprof_Timers[type]->accu.start;
    xprof_update(xp_UNACCOUNTED);
}

void
xprof_stop(xprof_type type, const char *timer)
{
    xprof_Timers[type]->accu.stop = get_tick();
    xprof_update(&xprof_Timers[type]->accu);
    if (--xprof_nesting)
	return;
    xp_UNACCOUNTED->start = xprof_Timers[type]->accu.stop;
    xprof_nesting = 0;
}

#endif /* USE_XPROF_STATS */
