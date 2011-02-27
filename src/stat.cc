/*
 * $Id$
 *
 * DEBUG: section 18    Cache Manager Statistics
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
#include "event.h"
#include "StoreClient.h"
#include "auth/UserRequest.h"
#include "CacheManager.h"
#include "Store.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "fde.h"
#include "mem_node.h"
#if DELAY_POOLS
#include "DelayId.h"
#endif
#include "client_side_request.h"
#include "client_side.h"
#include "MemBuf.h"
#include "SquidMath.h"
#include "SquidTime.h"

/* these are included because they expose stats calls */
/* TODO: provide a self registration mechanism for those classes
 * to use during static construction
 */
#include "comm.h"
#include "StoreSearch.h"

#define DEBUG_OPENFD 1

typedef int STOBJFLT(const StoreEntry *);

class StatObjectsState
{

public:
    StoreEntry *sentry;
    STOBJFLT *filter;
    StoreSearchPointer theSearch;

private:
    CBDATA_CLASS2(StatObjectsState);
};


/* LOCALS */
static const char *describeStatuses(const StoreEntry *);
static const char *describeTimestamps(const StoreEntry *);
static void statAvgTick(void *notused);
static void statAvgDump(StoreEntry *, int minutes, int hours);
#if STAT_GRAPHS
static void statGraphDump(StoreEntry *);
#endif
static void statCountersInit(StatCounters *);
static void statCountersInitSpecial(StatCounters *);
static void statCountersClean(StatCounters *);
static void statCountersCopy(StatCounters * dest, const StatCounters * orig);
static double statPctileSvc(double, int, int);
static void statStoreEntry(MemBuf * mb, StoreEntry * e);
static double statCPUUsage(int minutes);
static OBJH stat_io_get;
static OBJH stat_objects_get;
static OBJH stat_vmobjects_get;
#if DEBUG_OPENFD
static OBJH statOpenfdObj;
#endif
static EVH statObjects;
static OBJH info_get;
static OBJH statCountersDump;
static OBJH statPeerSelect;
static OBJH statDigestBlob;
static OBJH statAvg5min;
static OBJH statAvg60min;
static OBJH statUtilization;
static OBJH statCountersHistograms;
static OBJH statClientRequests;

#ifdef XMALLOC_STATISTICS
static void info_get_mallstat(int, int, int, void *);
static double xm_time;
static double xm_deltat;
#endif

StatCounters CountHist[N_COUNT_HIST];
static int NCountHist = 0;
static StatCounters CountHourHist[N_COUNT_HOUR_HIST];
static int NCountHourHist = 0;
CBDATA_CLASS_INIT(StatObjectsState);

extern unsigned int mem_pool_alloc_calls;
extern unsigned int mem_pool_free_calls;

static void
statUtilization(StoreEntry * e)
{
    storeAppendPrintf(e, "Cache Utilisation:\n");
    storeAppendPrintf(e, "\n");
    storeAppendPrintf(e, "Last 5 minutes:\n");

    if (NCountHist >= 5)
        statAvgDump(e, 5, 0);
    else
        storeAppendPrintf(e, "(no values recorded yet)\n");

    storeAppendPrintf(e, "\n");

    storeAppendPrintf(e, "Last 15 minutes:\n");

    if (NCountHist >= 15)
        statAvgDump(e, 15, 0);
    else
        storeAppendPrintf(e, "(no values recorded yet)\n");

    storeAppendPrintf(e, "\n");

    storeAppendPrintf(e, "Last hour:\n");

    if (NCountHist >= 60)
        statAvgDump(e, 60, 0);
    else
        storeAppendPrintf(e, "(no values recorded yet)\n");

    storeAppendPrintf(e, "\n");

    storeAppendPrintf(e, "Last 8 hours:\n");

    if (NCountHourHist >= 8)
        statAvgDump(e, 0, 8);
    else
        storeAppendPrintf(e, "(no values recorded yet)\n");

    storeAppendPrintf(e, "\n");

    storeAppendPrintf(e, "Last day:\n");

    if (NCountHourHist >= 24)
        statAvgDump(e, 0, 24);
    else
        storeAppendPrintf(e, "(no values recorded yet)\n");

    storeAppendPrintf(e, "\n");

    storeAppendPrintf(e, "Last 3 days:\n");

    if (NCountHourHist >= 72)
        statAvgDump(e, 0, 72);
    else
        storeAppendPrintf(e, "(no values recorded yet)\n");

    storeAppendPrintf(e, "\n");

    storeAppendPrintf(e, "Totals since cache startup:\n");

    statCountersDump(e);
}

static void
stat_io_get(StoreEntry * sentry)
{
    int i;

    storeAppendPrintf(sentry, "HTTP I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Http.reads);
    storeAppendPrintf(sentry, "Read Histogram:\n");

    for (i = 0; i < 16; i++) {
        storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
                          i ? (1 << (i - 1)) + 1 : 1,
                          1 << i,
                          IOStats.Http.read_hist[i],
                          Math::intPercent(IOStats.Http.read_hist[i], IOStats.Http.reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "FTP I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Ftp.reads);
    storeAppendPrintf(sentry, "Read Histogram:\n");

    for (i = 0; i < 16; i++) {
        storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
                          i ? (1 << (i - 1)) + 1 : 1,
                          1 << i,
                          IOStats.Ftp.read_hist[i],
                          Math::intPercent(IOStats.Ftp.read_hist[i], IOStats.Ftp.reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Gopher I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Gopher.reads);
    storeAppendPrintf(sentry, "Read Histogram:\n");

    for (i = 0; i < 16; i++) {
        storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
                          i ? (1 << (i - 1)) + 1 : 1,
                          1 << i,
                          IOStats.Gopher.read_hist[i],
                          Math::intPercent(IOStats.Gopher.read_hist[i], IOStats.Gopher.reads));
    }

    storeAppendPrintf(sentry, "\n");
}

static const char *
describeStatuses(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    snprintf(buf, 256, "%-13s %-13s %-12s %-12s",
             storeStatusStr[entry->store_status],
             memStatusStr[entry->mem_status],
             swapStatusStr[entry->swap_status],
             pingStatusStr[entry->ping_status]);
    return buf;
}

const char *
storeEntryFlags(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    int flags = (int) entry->flags;
    char *t;
    buf[0] = '\0';

    if (EBIT_TEST(flags, ENTRY_SPECIAL))
        strcat(buf, "SPECIAL,");

    if (EBIT_TEST(flags, ENTRY_REVALIDATE))
        strcat(buf, "REVALIDATE,");

    if (EBIT_TEST(flags, DELAY_SENDING))
        strcat(buf, "DELAY_SENDING,");

    if (EBIT_TEST(flags, RELEASE_REQUEST))
        strcat(buf, "RELEASE_REQUEST,");

    if (EBIT_TEST(flags, REFRESH_REQUEST))
        strcat(buf, "REFRESH_REQUEST,");

    if (EBIT_TEST(flags, ENTRY_CACHABLE))
        strcat(buf, "CACHABLE,");

    if (EBIT_TEST(flags, ENTRY_DISPATCHED))
        strcat(buf, "DISPATCHED,");

    if (EBIT_TEST(flags, KEY_PRIVATE))
        strcat(buf, "PRIVATE,");

    if (EBIT_TEST(flags, ENTRY_FWD_HDR_WAIT))
        strcat(buf, "FWD_HDR_WAIT,");

    if (EBIT_TEST(flags, ENTRY_NEGCACHED))
        strcat(buf, "NEGCACHED,");

    if (EBIT_TEST(flags, ENTRY_VALIDATED))
        strcat(buf, "VALIDATED,");

    if (EBIT_TEST(flags, ENTRY_BAD_LENGTH))
        strcat(buf, "BAD_LENGTH,");

    if (EBIT_TEST(flags, ENTRY_ABORTED))
        strcat(buf, "ABORTED,");

    if ((t = strrchr(buf, ',')))
        *t = '\0';

    return buf;
}

static const char *
describeTimestamps(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    snprintf(buf, 256, "LV:%-9d LU:%-9d LM:%-9d EX:%-9d",
             (int) entry->timestamp,
             (int) entry->lastref,
             (int) entry->lastmod,
             (int) entry->expires);
    return buf;
}

static void
statStoreEntry(MemBuf * mb, StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    mb->Printf("KEY %s\n", e->getMD5Text());
    mb->Printf("\t%s\n", describeStatuses(e));
    mb->Printf("\t%s\n", storeEntryFlags(e));
    mb->Printf("\t%s\n", describeTimestamps(e));
    mb->Printf("\t%d locks, %d clients, %d refs\n",
               (int) e->lock_count,
               storePendingNClients(e),
               (int) e->refcount);
    mb->Printf("\tSwap Dir %d, File %#08X\n",
               e->swap_dirn, e->swap_filen);

    if (mem != NULL)
        mem->stat (mb);

    mb->Printf("\n");
}

/* process objects list */
static void
statObjects(void *data)
{
    StatObjectsState *state = static_cast<StatObjectsState *>(data);
    StoreEntry *e;

    if (state->theSearch->isDone()) {
        state->sentry->complete();
        state->sentry->unlock();
        cbdataFree(state);
        return;
    } else if (EBIT_TEST(state->sentry->flags, ENTRY_ABORTED)) {
        state->sentry->unlock();
        cbdataFree(state);
        return;
    } else if (state->sentry->checkDeferRead(-1)) {
        eventAdd("statObjects", statObjects, state, 0.1, 1);
        return;
    }

    state->sentry->buffer();
    size_t statCount = 0;
    MemBuf mb;
    mb.init();

    while (statCount++ < static_cast<size_t>(Config.Store.objectsPerBucket) && state->
            theSearch->next()) {
        e = state->theSearch->currentItem();

        if (state->filter && 0 == state->filter(e))
            continue;

        statStoreEntry(&mb, e);
    }

    if (mb.size)
        state->sentry->append(mb.buf, mb.size);
    mb.clean();

    eventAdd("statObjects", statObjects, state, 0.0, 1);
}

static void
statObjectsStart(StoreEntry * sentry, STOBJFLT * filter)
{
    StatObjectsState *state = new StatObjectsState;
    state->sentry = sentry;
    state->filter = filter;

    sentry->lock();
    state->theSearch = Store::Root().search(NULL, NULL);

    eventAdd("statObjects", statObjects, state, 0.0, 1);
}

static void
stat_objects_get(StoreEntry * sentry)
{
    statObjectsStart(sentry, NULL);
}

static int
statObjectsVmFilter(const StoreEntry * e)
{
    return e->mem_obj ? 1 : 0;
}

static void
stat_vmobjects_get(StoreEntry * sentry)
{
    statObjectsStart(sentry, statObjectsVmFilter);
}

#if DEBUG_OPENFD
static int
statObjectsOpenfdFilter(const StoreEntry * e)
{
    if (e->mem_obj == NULL)
        return 0;

    if (e->mem_obj->swapout.sio == NULL)
        return 0;

    return 1;
}

static void
statOpenfdObj(StoreEntry * sentry)
{
    statObjectsStart(sentry, statObjectsOpenfdFilter);
}

#endif

#ifdef XMALLOC_STATISTICS
static void
info_get_mallstat(int size, int number, int oldnum, void *data)
{
    StoreEntry *sentry = (StoreEntry *)data;

// format: "%12s %15s %6s %12s\n","Alloc Size","Count","Delta","Alloc/sec"
    if (number > 0)
        storeAppendPrintf(sentry, "%12d %15d %6d %.1f\n", size, number, number - oldnum, xdiv((number - oldnum), xm_deltat));
}

#endif

static void
info_get(StoreEntry * sentry)
{

    struct rusage rusage;
    double cputime;
    double runtime;

    runtime = tvSubDsec(squid_start, current_time);

    if (runtime == 0.0)
        runtime = 1.0;

    storeAppendPrintf(sentry, "Squid Object Cache: Version %s\n",
                      version_string);

#ifdef _SQUID_WIN32_

    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        storeAppendPrintf(sentry,"\nRunning as %s Windows System Service on %s\n",
                          WIN32_Service_name, WIN32_OS_string);
        storeAppendPrintf(sentry,"Service command line is: %s\n", WIN32_Service_Command_Line);
    } else
        storeAppendPrintf(sentry,"Running on %s\n",WIN32_OS_string);

#endif

    storeAppendPrintf(sentry, "Start Time:\t%s\n",
                      mkrfc1123(squid_start.tv_sec));

    storeAppendPrintf(sentry, "Current Time:\t%s\n",
                      mkrfc1123(current_time.tv_sec));

    storeAppendPrintf(sentry, "Connection information for %s:\n",APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tNumber of clients accessing cache:\t%u\n",
                      statCounter.client_http.clients);

    storeAppendPrintf(sentry, "\tNumber of HTTP requests received:\t%u\n",
                      statCounter.client_http.requests);

    storeAppendPrintf(sentry, "\tNumber of ICP messages received:\t%u\n",
                      statCounter.icp.pkts_recv);

    storeAppendPrintf(sentry, "\tNumber of ICP messages sent:\t%u\n",
                      statCounter.icp.pkts_sent);

    storeAppendPrintf(sentry, "\tNumber of queued ICP replies:\t%u\n",
                      statCounter.icp.replies_queued);

#if USE_HTCP

    storeAppendPrintf(sentry, "\tNumber of HTCP messages received:\t%u\n",
                      statCounter.htcp.pkts_recv);

    storeAppendPrintf(sentry, "\tNumber of HTCP messages sent:\t%u\n",
                      statCounter.htcp.pkts_sent);

#endif

    storeAppendPrintf(sentry, "\tRequest failure ratio:\t%5.2f\n",
                      request_failure_ratio);

    storeAppendPrintf(sentry, "\tAverage HTTP requests per minute since start:\t%.1f\n",
                      statCounter.client_http.requests / (runtime / 60.0));

    storeAppendPrintf(sentry, "\tAverage ICP messages per minute since start:\t%.1f\n",
                      (statCounter.icp.pkts_sent + statCounter.icp.pkts_recv) / (runtime / 60.0));

    storeAppendPrintf(sentry, "\tSelect loop called: %ld times, %0.3f ms avg\n",
                      statCounter.select_loops, 1000.0 * runtime / statCounter.select_loops);

    storeAppendPrintf(sentry, "Cache information for %s:\n",APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tHits as %% of all requests:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      statRequestHitRatio(5),
                      statRequestHitRatio(60));

    storeAppendPrintf(sentry, "\tHits as %% of bytes sent:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      statByteHitRatio(5),
                      statByteHitRatio(60));

    storeAppendPrintf(sentry, "\tMemory hits as %% of hit requests:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      statRequestHitMemoryRatio(5),
                      statRequestHitMemoryRatio(60));

    storeAppendPrintf(sentry, "\tDisk hits as %% of hit requests:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      statRequestHitDiskRatio(5),
                      statRequestHitDiskRatio(60));

    storeAppendPrintf(sentry, "\tStorage Swap size:\t%lu KB\n",
                      store_swap_size);

    storeAppendPrintf(sentry, "\tStorage Swap capacity:\t%4.1f%% used, %4.1f%% free\n",
                      Math::doublePercent(store_swap_size, Store::Root().maxSize()),
                      Math::doublePercent((Store::Root().maxSize() - store_swap_size), Store::Root().maxSize()));


    storeAppendPrintf(sentry, "\tStorage Mem size:\t%lu KB\n",
                      (unsigned long)(mem_node::StoreMemSize() >> 10));

    double mFree = 0.0;
    if (mem_node::InUseCount() <= store_pages_max)
        mFree = Math::doublePercent((store_pages_max - mem_node::InUseCount()), store_pages_max);
    storeAppendPrintf(sentry, "\tStorage Mem capacity:\t%4.1f%% used, %4.1f%% free\n",
                      Math::doublePercent(mem_node::InUseCount(), store_pages_max),
                      mFree);

    storeAppendPrintf(sentry, "\tMean Object Size:\t%0.2f KB\n",
                      n_disk_objects ? (double) store_swap_size / n_disk_objects : 0.0);

    storeAppendPrintf(sentry, "\tRequests given to unlinkd:\t%ld\n",
                      (long)statCounter.unlink.requests);

    storeAppendPrintf(sentry, "Median Service Times (seconds)  5 min    60 min:\n");

    storeAppendPrintf(sentry, "\tHTTP Requests (All):  %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_HTTP) / 1000.0,
                      statPctileSvc(0.5, 60, PCTILE_HTTP) / 1000.0);

    storeAppendPrintf(sentry, "\tCache Misses:         %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_MISS) / 1000.0,
                      statPctileSvc(0.5, 60, PCTILE_MISS) / 1000.0);

    storeAppendPrintf(sentry, "\tCache Hits:           %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_HIT) / 1000.0,
                      statPctileSvc(0.5, 60, PCTILE_HIT) / 1000.0);

    storeAppendPrintf(sentry, "\tNear Hits:            %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_NH) / 1000.0,
                      statPctileSvc(0.5, 60, PCTILE_NH) / 1000.0);

    storeAppendPrintf(sentry, "\tNot-Modified Replies: %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_NM) / 1000.0,
                      statPctileSvc(0.5, 60, PCTILE_NM) / 1000.0);

    storeAppendPrintf(sentry, "\tDNS Lookups:          %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_DNS) / 1000.0,
                      statPctileSvc(0.5, 60, PCTILE_DNS) / 1000.0);

    storeAppendPrintf(sentry, "\tICP Queries:          %8.5f %8.5f\n",
                      statPctileSvc(0.5, 5, PCTILE_ICP_QUERY) / 1000000.0,
                      statPctileSvc(0.5, 60, PCTILE_ICP_QUERY) / 1000000.0);

    squid_getrusage(&rusage);

    cputime = rusage_cputime(&rusage);

    storeAppendPrintf(sentry, "Resource usage for %s:\n", APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tUP Time:\t%.3f seconds\n", runtime);

    storeAppendPrintf(sentry, "\tCPU Time:\t%.3f seconds\n", cputime);

    storeAppendPrintf(sentry, "\tCPU Usage:\t%.2f%%\n",
                      Math::doublePercent(cputime, runtime));

    storeAppendPrintf(sentry, "\tCPU Usage, 5 minute avg:\t%.2f%%\n",
                      statCPUUsage(5));

    storeAppendPrintf(sentry, "\tCPU Usage, 60 minute avg:\t%.2f%%\n",
                      statCPUUsage(60));

#if HAVE_SBRK

    storeAppendPrintf(sentry, "\tProcess Data Segment Size via sbrk(): %lu KB\n",
                      (unsigned long) (((char *) sbrk(0) - (char *) sbrk_start) >> 10));

#endif

    storeAppendPrintf(sentry, "\tMaximum Resident Size: %ld KB\n",
                      (long)rusage_maxrss(&rusage));

    storeAppendPrintf(sentry, "\tPage faults with physical i/o: %ld\n",
                      (long)rusage_pagefaults(&rusage));

#if HAVE_MSTATS && HAVE_GNUMALLOC_H


    struct mstats ms = mstats();

    storeAppendPrintf(sentry, "Memory usage for %s via mstats():\n",APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tTotal space in arena:  %6.0f KB\n",
                      static_cast<double>(ms.bytes_total / 1024));

    storeAppendPrintf(sentry, "\tTotal free:            %6.0f KB %.0f%%\n",
                      static_cast<double>(ms.bytes_free / 1024),
                      Math::doublePercent(static_cast<double>(ms.bytes_free), static_cast<double>(ms.bytes_total)));

#elif HAVE_MALLINFO && HAVE_STRUCT_MALLINFO

    struct mallinfo mp = mallinfo();

    storeAppendPrintf(sentry, "Memory usage for %s via mallinfo():\n",APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tTotal space in arena:  %6.0f KB\n",
                      static_cast<double>(mp.arena / 1024));

    storeAppendPrintf(sentry, "\tOrdinary blocks:       %6.0f KB %6.0f blks\n",
                      static_cast<double>(mp.uordblks / 1024), static_cast<double>(mp.ordblks));

    storeAppendPrintf(sentry, "\tSmall blocks:          %6.0f KB %6.0f blks\n",
                      static_cast<double>(mp.usmblks / 1024), static_cast<double>(mp.smblks));

    storeAppendPrintf(sentry, "\tHolding blocks:        %6.0f KB %6.0f blks\n",
                      static_cast<double>(mp.hblkhd / 1024), static_cast<double>(mp.hblks));

    storeAppendPrintf(sentry, "\tFree Small blocks:     %6.0f KB\n",
                      static_cast<double>(mp.fsmblks / 1024));

    storeAppendPrintf(sentry, "\tFree Ordinary blocks:  %6.0f KB\n",
                      static_cast<double>(mp.fordblks / 1024));

    double t = mp.uordblks + mp.usmblks + mp.hblkhd;

    storeAppendPrintf(sentry, "\tTotal in use:          %6.0f KB %.0f%%\n",
                      (t / 1024), Math::doublePercent(t, static_cast<double>(mp.arena + mp.hblkhd)));

    t = mp.fsmblks + mp.fordblks;

    storeAppendPrintf(sentry, "\tTotal free:            %6.0f KB %.0f%%\n",
                      (t / 1024), Math::doublePercent(t, static_cast<double>(mp.arena + mp.hblkhd)));

    t = mp.arena + mp.hblkhd;

    storeAppendPrintf(sentry, "\tTotal size:            %6.0f KB\n", (t / 1024));

#if HAVE_STRUCT_MALLINFO_MXFAST

    storeAppendPrintf(sentry, "\tmax size of small blocks:\t%.0f\n", static_cast<double>(mp.mxfast));

    storeAppendPrintf(sentry, "\tnumber of small blocks in a holding block:\t%6.0f\n",
                      static_cast<double>(mp.nlblks));

    storeAppendPrintf(sentry, "\tsmall block rounding factor:\t%.0f\n", static_cast<double>(mp.grain));

    storeAppendPrintf(sentry, "\tspace (including overhead) allocated in ord. blks:\t%.0f\n",
                      static_cast<double>(mp.uordbytes));

    storeAppendPrintf(sentry, "\tnumber of ordinary blocks allocated:\t%.0f\n",
                      static_cast<double>(mp.allocated));

    storeAppendPrintf(sentry, "\tbytes used in maintaining the free tree:\t%.0f\n",
                      static_cast<double>(mp.treeoverhead));

#endif /* HAVE_STRUCT_MALLINFO_MXFAST */
#endif /* HAVE_MALLINFO */

    storeAppendPrintf(sentry, "Memory accounted for:\n");

#if !(HAVE_MSTATS && HAVE_GNUMALLOC_H) && HAVE_MALLINFO && HAVE_STRUCT_MALLINFO

    storeAppendPrintf(sentry, "\tTotal accounted:       %6.0f KB %.0f%%\n",
                      (statMemoryAccounted() / 1024), Math::doublePercent(statMemoryAccounted(), t));

#else

    storeAppendPrintf(sentry, "\tTotal accounted:       %6.0f KB\n",
                      (statMemoryAccounted() / 1024));

#endif
    {
        MemPoolGlobalStats mp_stats;
        memPoolGetGlobalStats(&mp_stats);
#if !(HAVE_MSTATS && HAVE_GNUMALLOC_H) && HAVE_MALLINFO && HAVE_STRUCT_MALLINFO

        storeAppendPrintf(sentry, "\tmemPool accounted:     %6.0f KB %.0f%%\n",
                          static_cast<double>(mp_stats.TheMeter->alloc.level / 1024),
                          Math::doublePercent(static_cast<double>(mp_stats.TheMeter->alloc.level), t));

        double iFree = 0;
        if (t >= mp_stats.TheMeter->alloc.level)
            iFree = Math::doublePercent((t - static_cast<double>(mp_stats.TheMeter->alloc.level)), t);
        storeAppendPrintf(sentry, "\tmemPool unaccounted:   %6.0f KB %.0f%%\n",
                          static_cast<double>((t - mp_stats.TheMeter->alloc.level) / 1024), iFree);
#endif

        storeAppendPrintf(sentry, "\tmemPoolAlloc calls: %9.0f\n",
                          mp_stats.TheMeter->gb_saved.count);
        storeAppendPrintf(sentry, "\tmemPoolFree calls:  %9.0f\n",
                          mp_stats.TheMeter->gb_freed.count);
    }

    storeAppendPrintf(sentry, "File descriptor usage for %s:\n", APP_SHORTNAME);
    storeAppendPrintf(sentry, "\tMaximum number of file descriptors:   %4d\n",
                      Squid_MaxFD);
    storeAppendPrintf(sentry, "\tLargest file desc currently in use:   %4d\n",
                      Biggest_FD);
    storeAppendPrintf(sentry, "\tNumber of file desc currently in use: %4d\n",
                      Number_FD);
    storeAppendPrintf(sentry, "\tFiles queued for open:                %4d\n",
                      Opening_FD);
    storeAppendPrintf(sentry, "\tAvailable number of file descriptors: %4d\n",
                      fdNFree());
    storeAppendPrintf(sentry, "\tReserved number of file descriptors:  %4d\n",
                      RESERVED_FD);
    storeAppendPrintf(sentry, "\tStore Disk files open:                %4d\n",
                      store_open_disk_fd);

    storeAppendPrintf(sentry, "Internal Data Structures:\n");
    storeAppendPrintf(sentry, "\t%6lu StoreEntries\n",
                      (unsigned long)StoreEntry::inUseCount());
    storeAppendPrintf(sentry, "\t%6lu StoreEntries with MemObjects\n",
                      (unsigned long)MemObject::inUseCount());
    storeAppendPrintf(sentry, "\t%6ld Hot Object Cache Items\n",
                      (long)hot_obj_count);
    storeAppendPrintf(sentry, "\t%6ld on-disk objects\n",
                      (long)n_disk_objects);

#if XMALLOC_STATISTICS

    xm_deltat = current_dtime - xm_time;
    xm_time = current_dtime;
    storeAppendPrintf(sentry, "\nMemory allocation statistics\n");
    storeAppendPrintf(sentry, "%12s %15s %6s %12s\n","Alloc Size","Count","Delta","Alloc/sec");
    malloc_statistics(info_get_mallstat, sentry);
#endif
}

static void
service_times(StoreEntry * sentry)
{
    int p;
    storeAppendPrintf(sentry, "Service Time Percentiles            5 min    60 min:\n");
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tHTTP Requests (All):  %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_HTTP) / 1000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_HTTP) / 1000.0);
    }
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tCache Misses:         %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_MISS) / 1000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_MISS) / 1000.0);
    }
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tCache Hits:           %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_HIT) / 1000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_HIT) / 1000.0);
    }
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tNear Hits:            %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_NH) / 1000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_NH) / 1000.0);
    }
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tNot-Modified Replies: %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_NM) / 1000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_NM) / 1000.0);
    }
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tDNS Lookups:          %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_DNS) / 1000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_DNS) / 1000.0);
    }
    for (p = 5; p < 100; p += 5) {
        storeAppendPrintf(sentry, "\tICP Queries:          %2d%%  %8.5f %8.5f\n",
                          p,
                          statPctileSvc((double) p / 100.0, 5, PCTILE_ICP_QUERY) / 1000000.0,
                          statPctileSvc((double) p / 100.0, 60, PCTILE_ICP_QUERY) / 1000000.0);
    }
}

#define XAVG(X) (dt ? (double) (f->X - l->X) / dt : 0.0)
static void
statAvgDump(StoreEntry * sentry, int minutes, int hours)
{
    StatCounters *f;
    StatCounters *l;
    double dt;
    double ct;
    double x;
    assert(N_COUNT_HIST > 1);
    assert(minutes > 0 || hours > 0);
    f = &CountHist[0];
    l = f;

    if (minutes > 0 && hours == 0) {
        /* checking minute readings ... */

        if (minutes > N_COUNT_HIST - 1)
            minutes = N_COUNT_HIST - 1;

        l = &CountHist[minutes];
    } else if (minutes == 0 && hours > 0) {
        /* checking hour readings ... */

        if (hours > N_COUNT_HOUR_HIST - 1)
            hours = N_COUNT_HOUR_HIST - 1;

        l = &CountHourHist[hours];
    } else {
        debugs(18, 1, "statAvgDump: Invalid args, minutes=" << minutes << ", hours=" << hours);
        return;
    }

    dt = tvSubDsec(l->timestamp, f->timestamp);
    ct = f->cputime - l->cputime;

    storeAppendPrintf(sentry, "sample_start_time = %d.%d (%s)\n",
                      (int) l->timestamp.tv_sec,
                      (int) l->timestamp.tv_usec,
                      mkrfc1123(l->timestamp.tv_sec));
    storeAppendPrintf(sentry, "sample_end_time = %d.%d (%s)\n",
                      (int) f->timestamp.tv_sec,
                      (int) f->timestamp.tv_usec,
                      mkrfc1123(f->timestamp.tv_sec));

    storeAppendPrintf(sentry, "client_http.requests = %f/sec\n",
                      XAVG(client_http.requests));
    storeAppendPrintf(sentry, "client_http.hits = %f/sec\n",
                      XAVG(client_http.hits));
    storeAppendPrintf(sentry, "client_http.errors = %f/sec\n",
                      XAVG(client_http.errors));
    storeAppendPrintf(sentry, "client_http.kbytes_in = %f/sec\n",
                      XAVG(client_http.kbytes_in.kb));
    storeAppendPrintf(sentry, "client_http.kbytes_out = %f/sec\n",
                      XAVG(client_http.kbytes_out.kb));

    x = statHistDeltaMedian(&l->client_http.all_svc_time,
                            &f->client_http.all_svc_time);
    storeAppendPrintf(sentry, "client_http.all_median_svc_time = %f seconds\n",
                      x / 1000.0);
    x = statHistDeltaMedian(&l->client_http.miss_svc_time,
                            &f->client_http.miss_svc_time);
    storeAppendPrintf(sentry, "client_http.miss_median_svc_time = %f seconds\n",
                      x / 1000.0);
    x = statHistDeltaMedian(&l->client_http.nm_svc_time,
                            &f->client_http.nm_svc_time);
    storeAppendPrintf(sentry, "client_http.nm_median_svc_time = %f seconds\n",
                      x / 1000.0);
    x = statHistDeltaMedian(&l->client_http.nh_svc_time,
                            &f->client_http.nh_svc_time);
    storeAppendPrintf(sentry, "client_http.nh_median_svc_time = %f seconds\n",
                      x / 1000.0);
    x = statHistDeltaMedian(&l->client_http.hit_svc_time,
                            &f->client_http.hit_svc_time);
    storeAppendPrintf(sentry, "client_http.hit_median_svc_time = %f seconds\n",
                      x / 1000.0);

    storeAppendPrintf(sentry, "server.all.requests = %f/sec\n",
                      XAVG(server.all.requests));
    storeAppendPrintf(sentry, "server.all.errors = %f/sec\n",
                      XAVG(server.all.errors));
    storeAppendPrintf(sentry, "server.all.kbytes_in = %f/sec\n",
                      XAVG(server.all.kbytes_in.kb));
    storeAppendPrintf(sentry, "server.all.kbytes_out = %f/sec\n",
                      XAVG(server.all.kbytes_out.kb));

    storeAppendPrintf(sentry, "server.http.requests = %f/sec\n",
                      XAVG(server.http.requests));
    storeAppendPrintf(sentry, "server.http.errors = %f/sec\n",
                      XAVG(server.http.errors));
    storeAppendPrintf(sentry, "server.http.kbytes_in = %f/sec\n",
                      XAVG(server.http.kbytes_in.kb));
    storeAppendPrintf(sentry, "server.http.kbytes_out = %f/sec\n",
                      XAVG(server.http.kbytes_out.kb));

    storeAppendPrintf(sentry, "server.ftp.requests = %f/sec\n",
                      XAVG(server.ftp.requests));
    storeAppendPrintf(sentry, "server.ftp.errors = %f/sec\n",
                      XAVG(server.ftp.errors));
    storeAppendPrintf(sentry, "server.ftp.kbytes_in = %f/sec\n",
                      XAVG(server.ftp.kbytes_in.kb));
    storeAppendPrintf(sentry, "server.ftp.kbytes_out = %f/sec\n",
                      XAVG(server.ftp.kbytes_out.kb));

    storeAppendPrintf(sentry, "server.other.requests = %f/sec\n",
                      XAVG(server.other.requests));
    storeAppendPrintf(sentry, "server.other.errors = %f/sec\n",
                      XAVG(server.other.errors));
    storeAppendPrintf(sentry, "server.other.kbytes_in = %f/sec\n",
                      XAVG(server.other.kbytes_in.kb));
    storeAppendPrintf(sentry, "server.other.kbytes_out = %f/sec\n",
                      XAVG(server.other.kbytes_out.kb));

    storeAppendPrintf(sentry, "icp.pkts_sent = %f/sec\n",
                      XAVG(icp.pkts_sent));
    storeAppendPrintf(sentry, "icp.pkts_recv = %f/sec\n",
                      XAVG(icp.pkts_recv));
    storeAppendPrintf(sentry, "icp.queries_sent = %f/sec\n",
                      XAVG(icp.queries_sent));
    storeAppendPrintf(sentry, "icp.replies_sent = %f/sec\n",
                      XAVG(icp.replies_sent));
    storeAppendPrintf(sentry, "icp.queries_recv = %f/sec\n",
                      XAVG(icp.queries_recv));
    storeAppendPrintf(sentry, "icp.replies_recv = %f/sec\n",
                      XAVG(icp.replies_recv));
    storeAppendPrintf(sentry, "icp.replies_queued = %f/sec\n",
                      XAVG(icp.replies_queued));
    storeAppendPrintf(sentry, "icp.query_timeouts = %f/sec\n",
                      XAVG(icp.query_timeouts));
    storeAppendPrintf(sentry, "icp.kbytes_sent = %f/sec\n",
                      XAVG(icp.kbytes_sent.kb));
    storeAppendPrintf(sentry, "icp.kbytes_recv = %f/sec\n",
                      XAVG(icp.kbytes_recv.kb));
    storeAppendPrintf(sentry, "icp.q_kbytes_sent = %f/sec\n",
                      XAVG(icp.q_kbytes_sent.kb));
    storeAppendPrintf(sentry, "icp.r_kbytes_sent = %f/sec\n",
                      XAVG(icp.r_kbytes_sent.kb));
    storeAppendPrintf(sentry, "icp.q_kbytes_recv = %f/sec\n",
                      XAVG(icp.q_kbytes_recv.kb));
    storeAppendPrintf(sentry, "icp.r_kbytes_recv = %f/sec\n",
                      XAVG(icp.r_kbytes_recv.kb));
    x = statHistDeltaMedian(&l->icp.query_svc_time, &f->icp.query_svc_time);
    storeAppendPrintf(sentry, "icp.query_median_svc_time = %f seconds\n",
                      x / 1000000.0);
    x = statHistDeltaMedian(&l->icp.reply_svc_time, &f->icp.reply_svc_time);
    storeAppendPrintf(sentry, "icp.reply_median_svc_time = %f seconds\n",
                      x / 1000000.0);
    x = statHistDeltaMedian(&l->dns.svc_time, &f->dns.svc_time);
    storeAppendPrintf(sentry, "dns.median_svc_time = %f seconds\n",
                      x / 1000.0);
    storeAppendPrintf(sentry, "unlink.requests = %f/sec\n",
                      XAVG(unlink.requests));
    storeAppendPrintf(sentry, "page_faults = %f/sec\n",
                      XAVG(page_faults));
    storeAppendPrintf(sentry, "select_loops = %f/sec\n",
                      XAVG(select_loops));
    storeAppendPrintf(sentry, "select_fds = %f/sec\n",
                      XAVG(select_fds));
    storeAppendPrintf(sentry, "average_select_fd_period = %f/fd\n",
                      f->select_fds > l->select_fds ?
                      (f->select_time - l->select_time) / (f->select_fds - l->select_fds)
                      : 0.0);
    x = statHistDeltaMedian(&l->select_fds_hist, &f->select_fds_hist);
    storeAppendPrintf(sentry, "median_select_fds = %f\n", x);
    storeAppendPrintf(sentry, "swap.outs = %f/sec\n",
                      XAVG(swap.outs));
    storeAppendPrintf(sentry, "swap.ins = %f/sec\n",
                      XAVG(swap.ins));
    storeAppendPrintf(sentry, "swap.files_cleaned = %f/sec\n",
                      XAVG(swap.files_cleaned));
    storeAppendPrintf(sentry, "aborted_requests = %f/sec\n",
                      XAVG(aborted_requests));

#if USE_POLL
    storeAppendPrintf(sentry, "syscalls.polls = %f/sec\n", XAVG(syscalls.selects));
#elif defined(USE_SELECT) || defined(USE_SELECT_WIN32)
    storeAppendPrintf(sentry, "syscalls.selects = %f/sec\n", XAVG(syscalls.selects));
#endif

    storeAppendPrintf(sentry, "syscalls.disk.opens = %f/sec\n", XAVG(syscalls.disk.opens));
    storeAppendPrintf(sentry, "syscalls.disk.closes = %f/sec\n", XAVG(syscalls.disk.closes));
    storeAppendPrintf(sentry, "syscalls.disk.reads = %f/sec\n", XAVG(syscalls.disk.reads));
    storeAppendPrintf(sentry, "syscalls.disk.writes = %f/sec\n", XAVG(syscalls.disk.writes));
    storeAppendPrintf(sentry, "syscalls.disk.seeks = %f/sec\n", XAVG(syscalls.disk.seeks));
    storeAppendPrintf(sentry, "syscalls.disk.unlinks = %f/sec\n", XAVG(syscalls.disk.unlinks));
    storeAppendPrintf(sentry, "syscalls.sock.accepts = %f/sec\n", XAVG(syscalls.sock.accepts));
    storeAppendPrintf(sentry, "syscalls.sock.sockets = %f/sec\n", XAVG(syscalls.sock.sockets));
    storeAppendPrintf(sentry, "syscalls.sock.connects = %f/sec\n", XAVG(syscalls.sock.connects));
    storeAppendPrintf(sentry, "syscalls.sock.binds = %f/sec\n", XAVG(syscalls.sock.binds));
    storeAppendPrintf(sentry, "syscalls.sock.closes = %f/sec\n", XAVG(syscalls.sock.closes));
    storeAppendPrintf(sentry, "syscalls.sock.reads = %f/sec\n", XAVG(syscalls.sock.reads));
    storeAppendPrintf(sentry, "syscalls.sock.writes = %f/sec\n", XAVG(syscalls.sock.writes));
    storeAppendPrintf(sentry, "syscalls.sock.recvfroms = %f/sec\n", XAVG(syscalls.sock.recvfroms));
    storeAppendPrintf(sentry, "syscalls.sock.sendtos = %f/sec\n", XAVG(syscalls.sock.sendtos));

    storeAppendPrintf(sentry, "cpu_time = %f seconds\n", ct);
    storeAppendPrintf(sentry, "wall_time = %f seconds\n", dt);
    storeAppendPrintf(sentry, "cpu_usage = %f%%\n", Math::doublePercent(ct, dt));
}

static void
statRegisterWithCacheManager(void)
{
    CacheManager *manager = CacheManager::GetInstance();
    manager->registerAction("info", "General Runtime Information",
                            info_get, 0, 1);
    manager->registerAction("service_times", "Service Times (Percentiles)",
                            service_times, 0, 1);
    manager->registerAction("filedescriptors", "Process Filedescriptor Allocation",
                            fde::DumpStats, 0, 1);
    manager->registerAction("objects", "All Cache Objects", stat_objects_get, 0, 0);
    manager->registerAction("vm_objects", "In-Memory and In-Transit Objects",
                            stat_vmobjects_get, 0, 0);
    manager->registerAction("io", "Server-side network read() size histograms",
                            stat_io_get, 0, 1);
    manager->registerAction("counters", "Traffic and Resource Counters",
                            statCountersDump, 0, 1);
    manager->registerAction("peer_select", "Peer Selection Algorithms",
                            statPeerSelect, 0, 1);
    manager->registerAction("digest_stats", "Cache Digest and ICP blob",
                            statDigestBlob, 0, 1);
    manager->registerAction("5min", "5 Minute Average of Counters",
                            statAvg5min, 0, 1);
    manager->registerAction("60min", "60 Minute Average of Counters",
                            statAvg60min, 0, 1);
    manager->registerAction("utilization", "Cache Utilization",
                            statUtilization, 0, 1);
    manager->registerAction("histograms", "Full Histogram Counts",
                            statCountersHistograms, 0, 1);
    manager->registerAction("active_requests",
                            "Client-side Active Requests",
                            statClientRequests, 0, 1);
#if DEBUG_OPENFD
    manager->registerAction("openfd_objects", "Objects with Swapout files open",
                            statOpenfdObj, 0, 0);
#endif
#if STAT_GRAPHS
    manager->registerAction("graph_variables", "Display cache metrics graphically",
                            statGraphDump, 0, 1);
#endif
}


void
statInit(void)
{
    int i;
    debugs(18, 5, "statInit: Initializing...");

    for (i = 0; i < N_COUNT_HIST; i++)
        statCountersInit(&CountHist[i]);

    for (i = 0; i < N_COUNT_HOUR_HIST; i++)
        statCountersInit(&CountHourHist[i]);

    statCountersInit(&statCounter);

    eventAdd("statAvgTick", statAvgTick, NULL, (double) COUNT_INTERVAL, 1);

    ClientActiveRequests.head = NULL;

    ClientActiveRequests.tail = NULL;

    statRegisterWithCacheManager();
}

static void
statAvgTick(void *notused)
{
    StatCounters *t = &CountHist[0];
    StatCounters *p = &CountHist[1];
    StatCounters *c = &statCounter;

    struct rusage rusage;
    eventAdd("statAvgTick", statAvgTick, NULL, (double) COUNT_INTERVAL, 1);
    squid_getrusage(&rusage);
    c->page_faults = rusage_pagefaults(&rusage);
    c->cputime = rusage_cputime(&rusage);
    c->timestamp = current_time;
    /* even if NCountHist is small, we already Init()ed the tail */
    statCountersClean(CountHist + N_COUNT_HIST - 1);
    xmemmove(p, t, (N_COUNT_HIST - 1) * sizeof(StatCounters));
    statCountersCopy(t, c);
    NCountHist++;

    if ((NCountHist % COUNT_INTERVAL) == 0) {
        /* we have an hours worth of readings.  store previous hour */
        StatCounters *t2 = &CountHourHist[0];
        StatCounters *p2 = &CountHourHist[1];
        StatCounters *c2 = &CountHist[N_COUNT_HIST - 1];
        statCountersClean(CountHourHist + N_COUNT_HOUR_HIST - 1);
        xmemmove(p2, t2, (N_COUNT_HOUR_HIST - 1) * sizeof(StatCounters));
        statCountersCopy(t2, c2);
        NCountHourHist++;
    }

    if (Config.warnings.high_rptm > 0) {
        int i = (int) statPctileSvc(0.5, 20, PCTILE_HTTP);

        if (Config.warnings.high_rptm < i)
            debugs(18, 0, "WARNING: Median response time is " << i << " milliseconds");
    }

    if (Config.warnings.high_pf) {
        int i = (CountHist[0].page_faults - CountHist[1].page_faults);
        double dt = tvSubDsec(CountHist[0].timestamp, CountHist[1].timestamp);

        if (i > 0 && dt > 0.0) {
            i /= (int) dt;

            if (Config.warnings.high_pf < i)
                debugs(18, 0, "WARNING: Page faults occuring at " << i << "/sec");
        }
    }

    if (Config.warnings.high_memory) {
        size_t i = 0;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H

        struct mstats ms = mstats();
        i = ms.bytes_total;
#elif HAVE_MALLINFO && HAVE_STRUCT_MALLINFO

        struct mallinfo mp = mallinfo();
        i = mp.arena;
#elif HAVE_SBRK

        i = (size_t) ((char *) sbrk(0) - (char *) sbrk_start);
#endif

        if (Config.warnings.high_memory < i)
            debugs(18, 0, "WARNING: Memory usage at " << ((unsigned long int)(i >> 20)) << " MB");
    }
}

static void
statCountersInit(StatCounters * C)
{
    assert(C);
    memset(C, 0, sizeof(*C));
    C->timestamp = current_time;
    statCountersInitSpecial(C);
}

/* add special cases here as they arrive */
static void
statCountersInitSpecial(StatCounters * C)
{
    /*
     * HTTP svc_time hist is kept in milli-seconds; max of 3 hours.
     */
    statHistLogInit(&C->client_http.all_svc_time, 300, 0.0, 3600000.0 * 3.0);
    statHistLogInit(&C->client_http.miss_svc_time, 300, 0.0, 3600000.0 * 3.0);
    statHistLogInit(&C->client_http.nm_svc_time, 300, 0.0, 3600000.0 * 3.0);
    statHistLogInit(&C->client_http.nh_svc_time, 300, 0.0, 3600000.0 * 3.0);
    statHistLogInit(&C->client_http.hit_svc_time, 300, 0.0, 3600000.0 * 3.0);
    /*
     * ICP svc_time hist is kept in micro-seconds; max of 1 minute.
     */
    statHistLogInit(&C->icp.query_svc_time, 300, 0.0, 1000000.0 * 60.0);
    statHistLogInit(&C->icp.reply_svc_time, 300, 0.0, 1000000.0 * 60.0);
    /*
     * DNS svc_time hist is kept in milli-seconds; max of 10 minutes.
     */
    statHistLogInit(&C->dns.svc_time, 300, 0.0, 60000.0 * 10.0);
    /*
     * Cache Digest Stuff
     */
    statHistEnumInit(&C->cd.on_xition_count, CacheDigestHashFuncCount);
    statHistEnumInit(&C->comm_icp_incoming, INCOMING_ICP_MAX);
    statHistEnumInit(&C->comm_dns_incoming, INCOMING_DNS_MAX);
    statHistEnumInit(&C->comm_http_incoming, INCOMING_HTTP_MAX);
    statHistIntInit(&C->select_fds_hist, 256);	/* was SQUID_MAXFD, but it is way too much. It is OK to crop this statistics */
}

/* add special cases here as they arrive */
static void
statCountersClean(StatCounters * C)
{
    assert(C);
    statHistClean(&C->client_http.all_svc_time);
    statHistClean(&C->client_http.miss_svc_time);
    statHistClean(&C->client_http.nm_svc_time);
    statHistClean(&C->client_http.nh_svc_time);
    statHistClean(&C->client_http.hit_svc_time);
    statHistClean(&C->icp.query_svc_time);
    statHistClean(&C->icp.reply_svc_time);
    statHistClean(&C->dns.svc_time);
    statHistClean(&C->cd.on_xition_count);
    statHistClean(&C->comm_icp_incoming);
    statHistClean(&C->comm_dns_incoming);
    statHistClean(&C->comm_http_incoming);
    statHistClean(&C->select_fds_hist);
}

/* add special cases here as they arrive */
static void
statCountersCopy(StatCounters * dest, const StatCounters * orig)
{
    assert(dest && orig);
    /* this should take care of all the fields, but "special" ones */
    xmemcpy(dest, orig, sizeof(*dest));
    /* prepare space where to copy special entries */
    statCountersInitSpecial(dest);
    /* now handle special cases */
    /* note: we assert that histogram capacities do not change */
    statHistCopy(&dest->client_http.all_svc_time, &orig->client_http.all_svc_time);
    statHistCopy(&dest->client_http.miss_svc_time, &orig->client_http.miss_svc_time);
    statHistCopy(&dest->client_http.nm_svc_time, &orig->client_http.nm_svc_time);
    statHistCopy(&dest->client_http.nh_svc_time, &orig->client_http.nh_svc_time);
    statHistCopy(&dest->client_http.hit_svc_time, &orig->client_http.hit_svc_time);
    statHistCopy(&dest->icp.query_svc_time, &orig->icp.query_svc_time);
    statHistCopy(&dest->icp.reply_svc_time, &orig->icp.reply_svc_time);
    statHistCopy(&dest->dns.svc_time, &orig->dns.svc_time);
    statHistCopy(&dest->cd.on_xition_count, &orig->cd.on_xition_count);
    statHistCopy(&dest->comm_icp_incoming, &orig->comm_icp_incoming);
    statHistCopy(&dest->comm_http_incoming, &orig->comm_http_incoming);
    statHistCopy(&dest->select_fds_hist, &orig->select_fds_hist);
}

static void
statCountersHistograms(StoreEntry * sentry)
{
    StatCounters *f = &statCounter;
    storeAppendPrintf(sentry, "client_http.all_svc_time histogram:\n");
    statHistDump(&f->client_http.all_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "client_http.miss_svc_time histogram:\n");
    statHistDump(&f->client_http.miss_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "client_http.nm_svc_time histogram:\n");
    statHistDump(&f->client_http.nm_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "client_http.nh_svc_time histogram:\n");
    statHistDump(&f->client_http.nh_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "client_http.hit_svc_time histogram:\n");
    statHistDump(&f->client_http.hit_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "icp.query_svc_time histogram:\n");
    statHistDump(&f->icp.query_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "icp.reply_svc_time histogram:\n");
    statHistDump(&f->icp.reply_svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "dns.svc_time histogram:\n");
    statHistDump(&f->dns.svc_time, sentry, NULL);
    storeAppendPrintf(sentry, "select_fds_hist histogram:\n");
    statHistDump(&f->select_fds_hist, sentry, NULL);
}

static void
statCountersDump(StoreEntry * sentry)
{
    StatCounters *f = &statCounter;

    struct rusage rusage;
    squid_getrusage(&rusage);
    f->page_faults = rusage_pagefaults(&rusage);
    f->cputime = rusage_cputime(&rusage);

    storeAppendPrintf(sentry, "sample_time = %d.%d (%s)\n",
                      (int) f->timestamp.tv_sec,
                      (int) f->timestamp.tv_usec,
                      mkrfc1123(f->timestamp.tv_sec));
    storeAppendPrintf(sentry, "client_http.requests = %ld\n",
                      (long)f->client_http.requests);
    storeAppendPrintf(sentry, "client_http.hits = %ld\n",
                      (long)f->client_http.hits);
    storeAppendPrintf(sentry, "client_http.errors = %ld\n",
                      (long)f->client_http.errors);
    storeAppendPrintf(sentry, "client_http.kbytes_in = %ld\n",
                      (long)f->client_http.kbytes_in.kb);
    storeAppendPrintf(sentry, "client_http.kbytes_out = %ld\n",
                      (long)f->client_http.kbytes_out.kb);
    storeAppendPrintf(sentry, "client_http.hit_kbytes_out = %ld\n",
                      (long)f->client_http.hit_kbytes_out.kb);

    storeAppendPrintf(sentry, "server.all.requests = %ld\n",
                      (long)f->server.all.requests);
    storeAppendPrintf(sentry, "server.all.errors = %ld\n",
                      (long) f->server.all.errors);
    storeAppendPrintf(sentry, "server.all.kbytes_in = %ld\n",
                      (long) f->server.all.kbytes_in.kb);
    storeAppendPrintf(sentry, "server.all.kbytes_out = %ld\n",
                      (long) f->server.all.kbytes_out.kb);

    storeAppendPrintf(sentry, "server.http.requests = %ld\n",
                      (long) f->server.http.requests);
    storeAppendPrintf(sentry, "server.http.errors = %ld\n",
                      (long) f->server.http.errors);
    storeAppendPrintf(sentry, "server.http.kbytes_in = %ld\n",
                      (long) f->server.http.kbytes_in.kb);
    storeAppendPrintf(sentry, "server.http.kbytes_out = %ld\n",
                      (long) f->server.http.kbytes_out.kb);

    storeAppendPrintf(sentry, "server.ftp.requests = %ld\n",
                      (long) f->server.ftp.requests);
    storeAppendPrintf(sentry, "server.ftp.errors = %ld\n",
                      (long) f->server.ftp.errors);
    storeAppendPrintf(sentry, "server.ftp.kbytes_in = %ld\n",
                      (long) f->server.ftp.kbytes_in.kb);
    storeAppendPrintf(sentry, "server.ftp.kbytes_out = %ld\n",
                      (long) f->server.ftp.kbytes_out.kb);

    storeAppendPrintf(sentry, "server.other.requests = %ld\n",
                      (long) f->server.other.requests);
    storeAppendPrintf(sentry, "server.other.errors = %ld\n",
                      (long) f->server.other.errors);
    storeAppendPrintf(sentry, "server.other.kbytes_in = %ld\n",
                      (long) f->server.other.kbytes_in.kb);
    storeAppendPrintf(sentry, "server.other.kbytes_out = %ld\n",
                      (long) f->server.other.kbytes_out.kb);

    storeAppendPrintf(sentry, "icp.pkts_sent = %ld\n",
                      (long)f->icp.pkts_sent);
    storeAppendPrintf(sentry, "icp.pkts_recv = %ld\n",
                      (long)f->icp.pkts_recv);
    storeAppendPrintf(sentry, "icp.queries_sent = %ld\n",
                      (long)f->icp.queries_sent);
    storeAppendPrintf(sentry, "icp.replies_sent = %ld\n",
                      (long)f->icp.replies_sent);
    storeAppendPrintf(sentry, "icp.queries_recv = %ld\n",
                      (long)f->icp.queries_recv);
    storeAppendPrintf(sentry, "icp.replies_recv = %ld\n",
                      (long)f->icp.replies_recv);
    storeAppendPrintf(sentry, "icp.query_timeouts = %ld\n",
                      (long)f->icp.query_timeouts);
    storeAppendPrintf(sentry, "icp.replies_queued = %ld\n",
                      (long)f->icp.replies_queued);
    storeAppendPrintf(sentry, "icp.kbytes_sent = %ld\n",
                      (long) f->icp.kbytes_sent.kb);
    storeAppendPrintf(sentry, "icp.kbytes_recv = %ld\n",
                      (long) f->icp.kbytes_recv.kb);
    storeAppendPrintf(sentry, "icp.q_kbytes_sent = %ld\n",
                      (long) f->icp.q_kbytes_sent.kb);
    storeAppendPrintf(sentry, "icp.r_kbytes_sent = %ld\n",
                      (long) f->icp.r_kbytes_sent.kb);
    storeAppendPrintf(sentry, "icp.q_kbytes_recv = %ld\n",
                      (long) f->icp.q_kbytes_recv.kb);
    storeAppendPrintf(sentry, "icp.r_kbytes_recv = %ld\n",
                      (long) f->icp.r_kbytes_recv.kb);

#if USE_CACHE_DIGESTS

    storeAppendPrintf(sentry, "icp.times_used = %ld\n",
                      (long)f->icp.times_used);
    storeAppendPrintf(sentry, "cd.times_used = %ld\n",
                      (long)f->cd.times_used);
    storeAppendPrintf(sentry, "cd.msgs_sent = %ld\n",
                      (long)f->cd.msgs_sent);
    storeAppendPrintf(sentry, "cd.msgs_recv = %ld\n",
                      (long)f->cd.msgs_recv);
    storeAppendPrintf(sentry, "cd.memory = %ld\n",
                      (long) f->cd.memory.kb);
    storeAppendPrintf(sentry, "cd.local_memory = %ld\n",
                      (long) (store_digest ? store_digest->mask_size / 1024 : 0));
    storeAppendPrintf(sentry, "cd.kbytes_sent = %ld\n",
                      (long) f->cd.kbytes_sent.kb);
    storeAppendPrintf(sentry, "cd.kbytes_recv = %ld\n",
                      (long) f->cd.kbytes_recv.kb);
#endif

    storeAppendPrintf(sentry, "unlink.requests = %ld\n",
                      (long)f->unlink.requests);
    storeAppendPrintf(sentry, "page_faults = %ld\n",
                      (long)f->page_faults);
    storeAppendPrintf(sentry, "select_loops = %ld\n",
                      (long)f->select_loops);
    storeAppendPrintf(sentry, "cpu_time = %f\n",
                      f->cputime);
    storeAppendPrintf(sentry, "wall_time = %f\n",
                      tvSubDsec(f->timestamp, current_time));
    storeAppendPrintf(sentry, "swap.outs = %ld\n",
                      (long)f->swap.outs);
    storeAppendPrintf(sentry, "swap.ins = %ld\n",
                      (long)f->swap.ins);
    storeAppendPrintf(sentry, "swap.files_cleaned = %ld\n",
                      (long)f->swap.files_cleaned);
    storeAppendPrintf(sentry, "aborted_requests = %ld\n",
                      (long)f->aborted_requests);
}

void
statFreeMemory(void)
{
    int i;

    for (i = 0; i < N_COUNT_HIST; i++)
        statCountersClean(&CountHist[i]);

    for (i = 0; i < N_COUNT_HOUR_HIST; i++)
        statCountersClean(&CountHourHist[i]);
}

static void
statPeerSelect(StoreEntry * sentry)
{
#if USE_CACHE_DIGESTS
    StatCounters *f = &statCounter;
    peer *peer;
    const int tot_used = f->cd.times_used + f->icp.times_used;

    /* totals */
    cacheDigestGuessStatsReport(&f->cd.guess, sentry, "all peers");
    /* per-peer */
    storeAppendPrintf(sentry, "\nPer-peer statistics:\n");

    for (peer = getFirstPeer(); peer; peer = getNextPeer(peer)) {
        if (peer->digest)
            peerDigestStatsReport(peer->digest, sentry);
        else
            storeAppendPrintf(sentry, "\nNo peer digest from %s\n", peer->host);

        storeAppendPrintf(sentry, "\n");
    }

    storeAppendPrintf(sentry, "\nAlgorithm usage:\n");
    storeAppendPrintf(sentry, "Cache Digest: %7d (%3d%%)\n",
                      f->cd.times_used, xpercentInt(f->cd.times_used, tot_used));
    storeAppendPrintf(sentry, "Icp:          %7d (%3d%%)\n",
                      f->icp.times_used, xpercentInt(f->icp.times_used, tot_used));
    storeAppendPrintf(sentry, "Total:        %7d (%3d%%)\n",
                      tot_used, xpercentInt(tot_used, tot_used));
#else

    storeAppendPrintf(sentry, "peer digests are disabled; no stats is available.\n");
#endif
}

static void
statDigestBlob(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "\nCounters:\n");
    statCountersDump(sentry);
    storeAppendPrintf(sentry, "\n5 Min Averages:\n");
    statAvgDump(sentry, 5, 0);
    storeAppendPrintf(sentry, "\nHistograms:\n");
    statCountersHistograms(sentry);
    storeAppendPrintf(sentry, "\nPeer Digests:\n");
    statPeerSelect(sentry);
    storeAppendPrintf(sentry, "\nLocal Digest:\n");
    storeDigestReport(sentry);
}

static void
statAvg5min(StoreEntry * e)
{
    statAvgDump(e, 5, 0);
}

static void
statAvg60min(StoreEntry * e)
{
    statAvgDump(e, 60, 0);
}

static double
statPctileSvc(double pctile, int interval, int which)
{
    StatCounters *f;
    StatCounters *l;
    double x;
    assert(interval > 0);

    if (interval > N_COUNT_HIST - 1)
        interval = N_COUNT_HIST - 1;

    f = &CountHist[0];

    l = &CountHist[interval];

    assert(f);

    assert(l);

    switch (which) {

    case PCTILE_HTTP:
        x = statHistDeltaPctile(&l->client_http.all_svc_time, &f->client_http.all_svc_time, pctile);
        break;

    case PCTILE_HIT:
        x = statHistDeltaPctile(&l->client_http.hit_svc_time, &f->client_http.hit_svc_time, pctile);
        break;

    case PCTILE_MISS:
        x = statHistDeltaPctile(&l->client_http.miss_svc_time, &f->client_http.miss_svc_time, pctile);
        break;

    case PCTILE_NM:
        x = statHistDeltaPctile(&l->client_http.nm_svc_time, &f->client_http.nm_svc_time, pctile);
        break;

    case PCTILE_NH:
        x = statHistDeltaPctile(&l->client_http.nh_svc_time, &f->client_http.nh_svc_time, pctile);
        break;

    case PCTILE_ICP_QUERY:
        x = statHistDeltaPctile(&l->icp.query_svc_time, &f->icp.query_svc_time, pctile);
        break;

    case PCTILE_DNS:
        x = statHistDeltaPctile(&l->dns.svc_time, &f->dns.svc_time, pctile);
        break;

    default:
        debugs(49, 5, "statPctileSvc: unknown type.");
        x = 0;
    }

    return x;
}

StatCounters *
snmpStatGet(int minutes)
{
    return &CountHist[minutes];
}

int
stat5minClientRequests(void)
{
    assert(N_COUNT_HIST > 5);
    return statCounter.client_http.requests - CountHist[5].client_http.requests;
}

static double
statCPUUsage(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].cputime - CountHist[minutes].cputime,
                               tvSubDsec(CountHist[minutes].timestamp, CountHist[0].timestamp));
}

extern double
statRequestHitRatio(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].client_http.hits -
                               CountHist[minutes].client_http.hits,
                               CountHist[0].client_http.requests -
                               CountHist[minutes].client_http.requests);
}

extern double
statRequestHitMemoryRatio(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].client_http.mem_hits -
                               CountHist[minutes].client_http.mem_hits,
                               CountHist[0].client_http.hits -
                               CountHist[minutes].client_http.hits);
}

extern double
statRequestHitDiskRatio(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].client_http.disk_hits -
                               CountHist[minutes].client_http.disk_hits,
                               CountHist[0].client_http.hits -
                               CountHist[minutes].client_http.hits);
}

extern double
statByteHitRatio(int minutes)
{
    size_t s;
    size_t c;
#if USE_CACHE_DIGESTS

    size_t cd;
#endif
    /* size_t might be unsigned */
    assert(minutes < N_COUNT_HIST);
    c = CountHist[0].client_http.kbytes_out.kb - CountHist[minutes].client_http.kbytes_out.kb;
    s = CountHist[0].server.all.kbytes_in.kb - CountHist[minutes].server.all.kbytes_in.kb;
#if USE_CACHE_DIGESTS
    /*
     * This ugly hack is here to prevent the user from seeing a
     * negative byte hit ratio.  When we fetch a cache digest from
     * a neighbor, it gets treated like a cache miss because the
     * object is consumed internally.  Thus, we subtract cache
     * digest bytes out before calculating the byte hit ratio.
     */
    cd = CountHist[0].cd.kbytes_recv.kb - CountHist[minutes].cd.kbytes_recv.kb;

    if (s < cd)
        debugs(18, 1, "STRANGE: srv_kbytes=" << s << ", cd_kbytes=" << cd);

    s -= cd;

#endif

    if (c > s)
        return Math::doublePercent(c - s, c);
    else
        return (-1.0 * Math::doublePercent(s - c, c));
}

static void
statClientRequests(StoreEntry * s)
{
    dlink_node *i;
    ClientHttpRequest *http;
    StoreEntry *e;
    int fd;
    char buf[MAX_IPSTRLEN];

    for (i = ClientActiveRequests.head; i; i = i->next) {
        const char *p = NULL;
        http = static_cast<ClientHttpRequest *>(i->data);
        assert(http);
        ConnStateData * conn = http->getConn();
        storeAppendPrintf(s, "Connection: %p\n", conn);

        if (conn != NULL) {
            fd = conn->fd;
            storeAppendPrintf(s, "\tFD %d, read %"PRId64", wrote %"PRId64"\n", fd,
                              fd_table[fd].bytes_read, fd_table[fd].bytes_written);
            storeAppendPrintf(s, "\tFD desc: %s\n", fd_table[fd].desc);
            storeAppendPrintf(s, "\tin: buf %p, offset %ld, size %ld\n",
                              conn->in.buf, (long int) conn->in.notYetUsed, (long int) conn->in.allocatedSize);
            storeAppendPrintf(s, "\tpeer: %s:%d\n",
                              conn->peer.NtoA(buf,MAX_IPSTRLEN),
                              conn->peer.GetPort());
            storeAppendPrintf(s, "\tme: %s:%d\n",
                              conn->me.NtoA(buf,MAX_IPSTRLEN),
                              conn->me.GetPort());
            storeAppendPrintf(s, "\tnrequests: %d\n",
                              conn->nrequests);
        }

        storeAppendPrintf(s, "uri %s\n", http->uri);
        storeAppendPrintf(s, "logType %s\n", log_tags[http->logType]);
        storeAppendPrintf(s, "out.offset %ld, out.size %lu\n",
                          (long int) http->out.offset, (unsigned long int) http->out.size);
        storeAppendPrintf(s, "req_sz %ld\n", (long int) http->req_sz);
        e = http->storeEntry();
        storeAppendPrintf(s, "entry %p/%s\n", e, e ? e->getMD5Text() : "N/A");
#if 0
        /* Not a member anymore */
        e = http->old_entry;
        storeAppendPrintf(s, "old_entry %p/%s\n", e, e ? e->getMD5Text() : "N/A");
#endif

        storeAppendPrintf(s, "start %ld.%06d (%f seconds ago)\n",
                          (long int) http->start_time.tv_sec,
                          (int) http->start_time.tv_usec,
                          tvSubDsec(http->start_time, current_time));

        if (http->request->auth_user_request)
            p = http->request->auth_user_request->username();
        else if (http->request->extacl_user.defined()) {
            p = http->request->extacl_user.termedBuf();
        }

        if (!p && (conn != NULL && conn->rfc931[0]))
            p = conn->rfc931;

#if USE_SSL

        if (!p && conn != NULL)
            p = sslGetUserEmail(fd_table[conn->fd].ssl);

#endif

        if (!p)
            p = dash_str;

        storeAppendPrintf(s, "username %s\n", p);

#if DELAY_POOLS

        storeAppendPrintf(s, "delay_pool %d\n", DelayId::DelayClient(http).pool());

#endif

        storeAppendPrintf(s, "\n");
    }
}

#if STAT_GRAPHS
/*
 * urgh, i don't like these, but they do cut the amount of code down immensely
 */

#define GRAPH_PER_MIN(Y) \
    for (i=0;i<(N_COUNT_HIST-2);i++) { \
	dt = tvSubDsec(CountHist[i+1].timestamp, CountHist[i].timestamp); \
	if (dt <= 0.0) \
	    break; \
	storeAppendPrintf(e, "%lu,%0.2f:", \
	    CountHist[i].timestamp.tv_sec, \
	    ((CountHist[i].Y - CountHist[i+1].Y) / dt)); \
    }

#define GRAPH_PER_HOUR(Y) \
    for (i=0;i<(N_COUNT_HOUR_HIST-2);i++) { \
	dt = tvSubDsec(CountHourHist[i+1].timestamp, CountHourHist[i].timestamp); \
	if (dt <= 0.0) \
	    break; \
	storeAppendPrintf(e, "%lu,%0.2f:", \
	    CountHourHist[i].timestamp.tv_sec, \
	    ((CountHourHist[i].Y - CountHourHist[i+1].Y) / dt)); \
    }

#define GRAPH_TITLE(X,Y) storeAppendPrintf(e,"%s\t%s\t",X,Y);
#define GRAPH_END storeAppendPrintf(e,"\n");

#define GENGRAPH(X,Y,Z) \
    GRAPH_TITLE(Y,Z) \
    GRAPH_PER_MIN(X) \
    GRAPH_PER_HOUR(X) \
    GRAPH_END

static void
statGraphDump(StoreEntry * e)
{
    int i;
    double dt;

    GENGRAPH(client_http.requests, "client_http.requests", "Client HTTP requests/sec");
    GENGRAPH(client_http.hits, "client_http.hits", "Client HTTP hits/sec");
    GENGRAPH(client_http.errors, "client_http.errors", "Client HTTP errors/sec");
    GENGRAPH(client_http.kbytes_in.kb, "client_http.kbytes_in", "Client HTTP kbytes_in/sec");
    GENGRAPH(client_http.kbytes_out.kb, "client_http.kbytes_out", "Client HTTP kbytes_out/sec");

    /* XXX todo: http median service times */

    GENGRAPH(server.all.requests, "server.all.requests", "Server requests/sec");
    GENGRAPH(server.all.errors, "server.all.errors", "Server errors/sec");
    GENGRAPH(server.all.kbytes_in.kb, "server.all.kbytes_in", "Server total kbytes_in/sec");
    GENGRAPH(server.all.kbytes_out.kb, "server.all.kbytes_out", "Server total kbytes_out/sec");

    GENGRAPH(server.http.requests, "server.http.requests", "Server HTTP requests/sec");
    GENGRAPH(server.http.errors, "server.http.errors", "Server HTTP errors/sec");
    GENGRAPH(server.http.kbytes_in.kb, "server.http.kbytes_in", "Server HTTP kbytes_in/sec");
    GENGRAPH(server.http.kbytes_out.kb, "server.http.kbytes_out", "Server HTTP kbytes_out/sec");

    GENGRAPH(server.ftp.requests, "server.ftp.requests", "Server FTP requests/sec");
    GENGRAPH(server.ftp.errors, "server.ftp.errors", "Server FTP errors/sec");
    GENGRAPH(server.ftp.kbytes_in.kb, "server.ftp.kbytes_in", "Server FTP kbytes_in/sec");
    GENGRAPH(server.ftp.kbytes_out.kb, "server.ftp.kbytes_out", "Server FTP kbytes_out/sec");

    GENGRAPH(server.other.requests, "server.other.requests", "Server other requests/sec");
    GENGRAPH(server.other.errors, "server.other.errors", "Server other errors/sec");
    GENGRAPH(server.other.kbytes_in.kb, "server.other.kbytes_in", "Server other kbytes_in/sec");
    GENGRAPH(server.other.kbytes_out.kb, "server.other.kbytes_out", "Server other kbytes_out/sec");

    GENGRAPH(icp.pkts_sent, "icp.pkts_sent", "ICP packets sent/sec");
    GENGRAPH(icp.pkts_recv, "icp.pkts_recv", "ICP packets received/sec");
    GENGRAPH(icp.kbytes_sent.kb, "icp.kbytes_sent", "ICP kbytes_sent/sec");
    GENGRAPH(icp.kbytes_recv.kb, "icp.kbytes_recv", "ICP kbytes_received/sec");

    /* XXX todo: icp median service times */
    /* XXX todo: dns median service times */

    GENGRAPH(unlink.requests, "unlink.requests", "Cache File unlink requests/sec");
    GENGRAPH(page_faults, "page_faults", "System Page Faults/sec");
    GENGRAPH(select_loops, "select_loops", "System Select Loop calls/sec");
    GENGRAPH(cputime, "cputime", "CPU utilisation");
}

#endif /* STAT_GRAPHS */

double
statMemoryAccounted(void)
{
    return static_cast<double>(memPoolsTotalAllocated());
}
