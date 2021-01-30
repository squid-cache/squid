/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _PROFILER_H_
#define _PROFILER_H_

#ifdef __cplusplus
extern "C" {
#endif

// NP: CPU support for get_tick() determines whether we can profile.
//     always include get_tick.h first since it may undefine USE_XPROF_STATS

#include "profiler/get_tick.h"
#include "profiler/xprof_type.h"

#if !USE_XPROF_STATS

#define PROF_start(probename) ((void)0)
#define PROF_stop(probename) ((void)0)

#else /* USE_XPROF_STATS */

#define XP_NOBEST (hrtime_t)-1

typedef struct _xprof_stats_node xprof_stats_node;

typedef struct _xprof_stats_data xprof_stats_data;

struct _xprof_stats_data {
    hrtime_t start;
    hrtime_t stop;
    hrtime_t delta;
    hrtime_t best;
    hrtime_t worst;
    hrtime_t count;
    hrtime_t accum;
    int64_t summ;
};

struct _xprof_stats_node {
    const char *name;
    xprof_stats_data accu;
    xprof_stats_data hist;
};

typedef xprof_stats_node TimersArray[1];

/* public Data */
extern TimersArray *xprof_Timers;

/* Exported functions */
extern void xprof_start(xprof_type type, const char *timer);
extern void xprof_stop(xprof_type type, const char *timer);
extern void xprof_event(void *data);

#define PROF_start(probename) xprof_start(XPROF_##probename, #probename)
#define PROF_stop(probename) xprof_stop(XPROF_##probename, #probename)

#endif /* USE_XPROF_STATS */

#ifdef __cplusplus
}
#endif
#endif /* _PROFILING_H_ */

