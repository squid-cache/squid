/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 81    CPU Profiling Routines */

/**
 * CPU Profiling implementation.
 *
 * \par
 *  This library implements the Probes needed to gather stats.
 *  See src/ProfStats.c which implements historical recording and
 *  presentation in CacheMgr.cgi.
 *
 * \par
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
 *   probename must be added to the xprof_type.h enum list
 *   with prepended "XPROF_" string.
 *
 * \section description Description.
 * \par PROF
 *  gathers stats per probename into structures. It indexes these
 *  structures by enum type index in an array.
 *
 * \par PROF
 *  records best, best, average and worst values for delta time,
 *  also, if UNACCED is defined, it measures "empty" time during which
 *  no probes are in measuring state. This allows to see time "unaccounted"
 *  for. If OVERHEAD is defined, additional calculations are made at every
 *  probe to measure approximate overhead of the probe code itself.
 *
 * \par
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
 * \par
 *  For actual measurements, probe overhead cancels out mostly. Still,
 *  do not take the measured times as facts, they should be viewed in
 *  relative comparison to overall CPU time and on the same platform.
 *
 * \par
 *  Every 1 second, Event within squid is called that parses gathered
 *  statistics of every probe, and accumulates that into historical
 *  structures for last 1,5,30 secs, 1,5,30 mins, and 1,5 and 24 hours.
 *  Each second active probe stats are reset, and only historical data
 *  is presented in cachemgr output.
 *
 * \section reading Reading stats.
 * \par
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
 * \par
 *  TOTALS are quite off reality. Its there just to summarise cumulative
 *  times and percent column. Percent values over 100% shows that there
 *  have been some probes nested into each other.
 *
 */

#include "squid.h"
#include "profiler/Profiler.h"

#if USE_XPROF_STATS

#include <cassert>
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

/* Private stuff */

/* new stuff */
#define MAXSTACKDEPTH   512

struct _callstack_entry {
    int timer;      /* index into timers array */
    const char *name;
    hrtime_t start, stop, accum;
};

struct _callstack_entry cstack[MAXSTACKDEPTH];
int cstack_head = 0;

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
static __inline void
#else
static inline void
#endif
xprof_update(xprof_stats_data * head)
{
    if (head->delta < head->best)
        head->best = head->delta;
    if (head->worst < head->delta)
        head->worst = head->delta;
    head->summ += head->delta;
    ++head->count;
}

static xprof_stats_data *xp_UNACCOUNTED;
static int xprof_inited = 0;

static void
xprof_InitLib(void)
{
    if (xprof_inited)
        return;

    xprof_Timers = static_cast<TimersArray *>(calloc(XPROF_LAST + 2, sizeof(xprof_stats_node)));

    xprof_Timers[XPROF_PROF_UNACCOUNTED]->name = "PROF_UNACCOUNTED";
    xprof_Timers[XPROF_PROF_UNACCOUNTED]->accu.start = get_tick();
    xp_UNACCOUNTED = &xprof_Timers[XPROF_PROF_UNACCOUNTED]->accu;
    cstack_head = 0;
    xprof_inited = 1;
}

void
xprof_start(xprof_type type, const char *timer)
{
    hrtime_t tt = get_tick();
    if (!xprof_inited)
        xprof_InitLib();

    /* If nested, stop current stack frame */
    if (cstack_head > 0) {
        cstack[cstack_head - 1].accum += get_tick() - cstack[cstack_head - 1].start;
        cstack[cstack_head - 1].start = -1;
    }

    /* Are we at the first level? If so; stop the unaccounted timer */
    if (cstack_head == 0) {
        assert(xp_UNACCOUNTED->start != -1);
        xp_UNACCOUNTED->delta = tt - xp_UNACCOUNTED->start;
        xp_UNACCOUNTED->start = -1;
        xprof_update(xp_UNACCOUNTED);
    }

    /* Allocate new stack frame */
    cstack[cstack_head].start = tt;
    cstack[cstack_head].stop = -1;
    cstack[cstack_head].accum = 0;
    cstack[cstack_head].timer = type;
    cstack[cstack_head].name = timer;
    ++cstack_head;
    assert(cstack_head < MAXSTACKDEPTH);

}

void
xprof_stop(xprof_type type, const char *timer)
{
    hrtime_t tt = get_tick();
    assert(cstack_head > 0);
    --cstack_head;
    assert(cstack[cstack_head].timer == type);

    /* Record timer details */
    cstack[cstack_head].accum += tt - cstack[cstack_head].start;
    xprof_Timers[type]->accu.delta = cstack[cstack_head].accum;
    xprof_Timers[type]->name = timer;

    /* Update */
    xprof_update(&xprof_Timers[type]->accu);

    /* Restart previous timer if we're not at the top level */
    if (cstack_head > 0) {
        cstack[cstack_head - 1].start = tt;
        cstack[cstack_head - 1].stop = 0;
        return;
    }
    /* Get here? We're at the top level; unaccounted */
    xp_UNACCOUNTED->start = tt;
}

#endif /* USE_XPROF_STATS */

