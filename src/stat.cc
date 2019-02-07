/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 18    Cache Manager Statistics */

#include "squid.h"
#include "CacheDigest.h"
#include "CachePeer.h"
#include "client_side.h"
#include "client_side_request.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "event.h"
#include "fde.h"
#include "format/Token.h"
#include "globals.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "IoStats.h"
#include "mem/Pool.h"
#include "mem_node.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mgr/CountersAction.h"
#include "mgr/FunAction.h"
#include "mgr/InfoAction.h"
#include "mgr/IntervalAction.h"
#include "mgr/IoAction.h"
#include "mgr/Registration.h"
#include "mgr/ServiceTimesAction.h"
#include "neighbors.h"
#include "PeerDigest.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "stat.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_digest.h"
#include "StoreClient.h"
#include "tools.h"
// for tvSubDsec() which should be in SquidTime.h
#include "util.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "DelayId.h"
#endif
#if USE_OPENSSL
#include "ssl/support.h"
#endif

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
    CBDATA_CLASS(StatObjectsState);

public:
    StoreEntry *sentry;
    STOBJFLT *filter;
    StoreSearchPointer theSearch;
};

/* LOCALS */
static const char *describeStatuses(const StoreEntry *);
static void statAvgTick(void *notused);
static void statAvgDump(StoreEntry *, int minutes, int hours);
#if STAT_GRAPHS
static void statGraphDump(StoreEntry *);
#endif
static double statPctileSvc(double, int, int);
static void statStoreEntry(MemBuf * mb, StoreEntry * e);
static double statCPUUsage(int minutes);
static OBJH stat_objects_get;
static OBJH stat_vmobjects_get;
#if DEBUG_OPENFD
static OBJH statOpenfdObj;
#endif
static EVH statObjects;
static OBJH statCountersDump;
static OBJH statPeerSelect;
static OBJH statDigestBlob;
static OBJH statUtilization;
static OBJH statCountersHistograms;
static OBJH statClientRequests;
void GetAvgStat(Mgr::IntervalActionData& stats, int minutes, int hours);
void DumpAvgStat(Mgr::IntervalActionData& stats, StoreEntry* sentry);
void GetInfo(Mgr::InfoActionData& stats);
void DumpInfo(Mgr::InfoActionData& stats, StoreEntry* sentry);
void DumpMallocStatistics(StoreEntry* sentry);
void GetCountersStats(Mgr::CountersActionData& stats);
void DumpCountersStats(Mgr::CountersActionData& stats, StoreEntry* sentry);
void GetServiceTimesStats(Mgr::ServiceTimesActionData& stats);
void DumpServiceTimesStats(Mgr::ServiceTimesActionData& stats, StoreEntry* sentry);
void GetIoStats(Mgr::IoActionData& stats);
void DumpIoStats(Mgr::IoActionData& stats, StoreEntry* sentry);

#if XMALLOC_STATISTICS
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

void
GetIoStats(Mgr::IoActionData& stats)
{
    int i;

    stats.http_reads = IOStats.Http.reads;

    for (i = 0; i < IoStats::histSize; ++i) {
        stats.http_read_hist[i] = IOStats.Http.read_hist[i];
    }

    stats.ftp_reads = IOStats.Ftp.reads;

    for (i = 0; i < IoStats::histSize; ++i) {
        stats.ftp_read_hist[i] = IOStats.Ftp.read_hist[i];
    }

    stats.gopher_reads = IOStats.Gopher.reads;

    for (i = 0; i < IoStats::histSize; ++i) {
        stats.gopher_read_hist[i] = IOStats.Gopher.read_hist[i];
    }
}

void
DumpIoStats(Mgr::IoActionData& stats, StoreEntry* sentry)
{
    int i;

    storeAppendPrintf(sentry, "HTTP I/O\n");
    storeAppendPrintf(sentry, "number of reads: %.0f\n", stats.http_reads);
    storeAppendPrintf(sentry, "Read Histogram:\n");

    for (i = 0; i < IoStats::histSize; ++i) {
        storeAppendPrintf(sentry, "%5d-%5d: %9.0f %2.0f%%\n",
                          i ? (1 << (i - 1)) + 1 : 1,
                          1 << i,
                          stats.http_read_hist[i],
                          Math::doublePercent(stats.http_read_hist[i], stats.http_reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "FTP I/O\n");
    storeAppendPrintf(sentry, "number of reads: %.0f\n", stats.ftp_reads);
    storeAppendPrintf(sentry, "Read Histogram:\n");

    for (i = 0; i < IoStats::histSize; ++i) {
        storeAppendPrintf(sentry, "%5d-%5d: %9.0f %2.0f%%\n",
                          i ? (1 << (i - 1)) + 1 : 1,
                          1 << i,
                          stats.ftp_read_hist[i],
                          Math::doublePercent(stats.ftp_read_hist[i], stats.ftp_reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Gopher I/O\n");
    storeAppendPrintf(sentry, "number of reads: %.0f\n", stats.gopher_reads);
    storeAppendPrintf(sentry, "Read Histogram:\n");

    for (i = 0; i < IoStats::histSize; ++i) {
        storeAppendPrintf(sentry, "%5d-%5d: %9.0f %2.0f%%\n",
                          i ? (1 << (i - 1)) + 1 : 1,
                          1 << i,
                          stats.gopher_read_hist[i],
                          Math::doublePercent(stats.gopher_read_hist[i], stats.gopher_reads));
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

    if (EBIT_TEST(flags, ENTRY_REVALIDATE_ALWAYS))
        strcat(buf, "REVALIDATE_ALWAYS,");

    if (EBIT_TEST(flags, DELAY_SENDING))
        strcat(buf, "DELAY_SENDING,");

    if (EBIT_TEST(flags, RELEASE_REQUEST))
        strcat(buf, "RELEASE_REQUEST,");

    if (EBIT_TEST(flags, REFRESH_REQUEST))
        strcat(buf, "REFRESH_REQUEST,");

    if (EBIT_TEST(flags, ENTRY_REVALIDATE_STALE))
        strcat(buf, "REVALIDATE_STALE,");

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

static void
statStoreEntry(MemBuf * mb, StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    mb->appendf("KEY %s\n", e->getMD5Text());
    mb->appendf("\t%s\n", describeStatuses(e));
    mb->appendf("\t%s\n", storeEntryFlags(e));
    mb->appendf("\t%s\n", e->describeTimestamps());
    mb->appendf("\t%d locks, %d clients, %d refs\n", (int) e->locks(), storePendingNClients(e), (int) e->refcount);
    mb->appendf("\tSwap Dir %d, File %#08X\n", e->swap_dirn, e->swap_filen);

    if (mem != NULL)
        mem->stat (mb);

    mb->append("\n", 1);
}

/* process objects list */
static void
statObjects(void *data)
{
    StatObjectsState *state = static_cast<StatObjectsState *>(data);
    StoreEntry *e;

    if (state->theSearch->isDone()) {
        if (UsingSmp())
            storeAppendPrintf(state->sentry, "} by kid%d\n\n", KidIdentifier);
        state->sentry->complete();
        state->sentry->unlock("statObjects+isDone");
        delete state;
        return;
    } else if (EBIT_TEST(state->sentry->flags, ENTRY_ABORTED)) {
        state->sentry->unlock("statObjects+aborted");
        delete state;
        return;
    } else if (state->sentry->checkDeferRead(-1)) {
        state->sentry->flush();
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

    sentry->lock("statObjects");
    state->theSearch = Store::Root().search();

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

#if XMALLOC_STATISTICS
static void
info_get_mallstat(int size, int number, int oldnum, void *data)
{
    StoreEntry *sentry = (StoreEntry *)data;

// format: "%12s %15s %6s %12s\n","Alloc Size","Count","Delta","Alloc/sec"
    if (number > 0)
        storeAppendPrintf(sentry, "%12d %15d %6d %.1f\n", size, number, number - oldnum, xdiv((number - oldnum), xm_deltat));
}

#endif

void
GetInfo(Mgr::InfoActionData& stats)
{

    struct rusage rusage;
    double cputime;
    double runtime;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    struct mstats ms;
#endif

    runtime = tvSubDsec(squid_start, current_time);

    if (runtime == 0.0)
        runtime = 1.0;

    stats.squid_start = squid_start;

    stats.current_time = current_time;

    stats.client_http_clients = statCounter.client_http.clients;

    stats.client_http_requests = statCounter.client_http.requests;

    stats.icp_pkts_recv = statCounter.icp.pkts_recv;

    stats.icp_pkts_sent = statCounter.icp.pkts_sent;

    stats.icp_replies_queued = statCounter.icp.replies_queued;

#if USE_HTCP

    stats.htcp_pkts_recv = statCounter.htcp.pkts_recv;

    stats.htcp_pkts_sent = statCounter.htcp.pkts_sent;

#endif

    stats.request_failure_ratio = request_failure_ratio;

    stats.avg_client_http_requests = statCounter.client_http.requests / (runtime / 60.0);

    stats.avg_icp_messages = (statCounter.icp.pkts_sent + statCounter.icp.pkts_recv) / (runtime / 60.0);

    stats.select_loops = statCounter.select_loops;
    stats.avg_loop_time = 1000.0 * runtime / statCounter.select_loops;

    stats.request_hit_ratio5 = statRequestHitRatio(5);
    stats.request_hit_ratio60 = statRequestHitRatio(60);

    stats.byte_hit_ratio5 = statByteHitRatio(5);
    stats.byte_hit_ratio60 = statByteHitRatio(60);

    stats.request_hit_mem_ratio5 = statRequestHitMemoryRatio(5);
    stats.request_hit_mem_ratio60 = statRequestHitMemoryRatio(60);

    stats.request_hit_disk_ratio5 = statRequestHitDiskRatio(5);
    stats.request_hit_disk_ratio60 = statRequestHitDiskRatio(60);

    Store::Root().getStats(stats.store);

    stats.unlink_requests = statCounter.unlink.requests;

    stats.http_requests5 = statPctileSvc(0.5, 5, PCTILE_HTTP);
    stats.http_requests60 = statPctileSvc(0.5, 60, PCTILE_HTTP);

    stats.cache_misses5 = statPctileSvc(0.5, 5, PCTILE_MISS);
    stats.cache_misses60 = statPctileSvc(0.5, 60, PCTILE_MISS);

    stats.cache_hits5 = statPctileSvc(0.5, 5, PCTILE_HIT);
    stats.cache_hits60 = statPctileSvc(0.5, 60, PCTILE_HIT);

    stats.near_hits5 = statPctileSvc(0.5, 5, PCTILE_NH);
    stats.near_hits60 = statPctileSvc(0.5, 60, PCTILE_NH);

    stats.not_modified_replies5 = statPctileSvc(0.5, 5, PCTILE_NM);
    stats.not_modified_replies60 = statPctileSvc(0.5, 60, PCTILE_NM);

    stats.dns_lookups5 = statPctileSvc(0.5, 5, PCTILE_DNS);
    stats.dns_lookups60 = statPctileSvc(0.5, 60, PCTILE_DNS);

    stats.icp_queries5 = statPctileSvc(0.5, 5, PCTILE_ICP_QUERY);
    stats.icp_queries60 = statPctileSvc(0.5, 60, PCTILE_ICP_QUERY);

    squid_getrusage(&rusage);
    cputime = rusage_cputime(&rusage);

    stats.up_time = runtime;
    stats.cpu_time = cputime;
    stats.cpu_usage = Math::doublePercent(cputime, runtime);
    stats.cpu_usage5 = statCPUUsage(5);
    stats.cpu_usage60 = statCPUUsage(60);

    stats.maxrss = rusage_maxrss(&rusage);

    stats.page_faults = rusage_pagefaults(&rusage);

#if HAVE_MSTATS && HAVE_GNUMALLOC_H

    ms = mstats();

    stats.ms_bytes_total = ms.bytes_total;

    stats.ms_bytes_free = ms.bytes_free;

#endif

    stats.total_accounted = statMemoryAccounted();

    {
        MemPoolGlobalStats mp_stats;
        memPoolGetGlobalStats(&mp_stats);
        stats.gb_saved_count = mp_stats.TheMeter->gb_saved.count;
        stats.gb_freed_count = mp_stats.TheMeter->gb_freed.count;
    }

    stats.max_fd = Squid_MaxFD;
    stats.biggest_fd = Biggest_FD;
    stats.number_fd = Number_FD;
    stats.opening_fd = Opening_FD;
    stats.num_fd_free = fdNFree();
    stats.reserved_fd = RESERVED_FD;
}

void
DumpInfo(Mgr::InfoActionData& stats, StoreEntry* sentry)
{
    storeAppendPrintf(sentry, "Squid Object Cache: Version %s\n",
                      version_string);

    storeAppendPrintf(sentry, "Build Info: " SQUID_BUILD_INFO "\n");

#if _SQUID_WINDOWS_
    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        storeAppendPrintf(sentry,"\nRunning as " SQUIDSBUFPH " Windows System Service on %s\n",
                          SQUIDSBUFPRINT(service_name), WIN32_OS_string);
        storeAppendPrintf(sentry,"Service command line is: %s\n", WIN32_Service_Command_Line);
    } else
        storeAppendPrintf(sentry,"Running on %s\n",WIN32_OS_string);
#else
    storeAppendPrintf(sentry,"Service Name: " SQUIDSBUFPH "\n", SQUIDSBUFPRINT(service_name));
#endif

    storeAppendPrintf(sentry, "Start Time:\t%s\n",
                      mkrfc1123(stats.squid_start.tv_sec));

    storeAppendPrintf(sentry, "Current Time:\t%s\n",
                      mkrfc1123(stats.current_time.tv_sec));

    storeAppendPrintf(sentry, "Connection information for %s:\n",APP_SHORTNAME);

    if (Config.onoff.client_db)
        storeAppendPrintf(sentry, "\tNumber of clients accessing cache:\t%.0f\n", stats.client_http_clients);
    else
        sentry->append("\tNumber of clients accessing cache:\t(client_db off)\n", 52);

    storeAppendPrintf(sentry, "\tNumber of HTTP requests received:\t%.0f\n",
                      stats.client_http_requests);

    storeAppendPrintf(sentry, "\tNumber of ICP messages received:\t%.0f\n",
                      stats.icp_pkts_recv);

    storeAppendPrintf(sentry, "\tNumber of ICP messages sent:\t%.0f\n",
                      stats.icp_pkts_sent);

    storeAppendPrintf(sentry, "\tNumber of queued ICP replies:\t%.0f\n",
                      stats.icp_replies_queued);

#if USE_HTCP

    storeAppendPrintf(sentry, "\tNumber of HTCP messages received:\t%.0f\n",
                      stats.htcp_pkts_recv);

    storeAppendPrintf(sentry, "\tNumber of HTCP messages sent:\t%.0f\n",
                      stats.htcp_pkts_sent);

#endif

    double fct = stats.count > 1 ? stats.count : 1.0;
    storeAppendPrintf(sentry, "\tRequest failure ratio:\t%5.2f\n",
                      stats.request_failure_ratio / fct);

    storeAppendPrintf(sentry, "\tAverage HTTP requests per minute since start:\t%.1f\n",
                      stats.avg_client_http_requests);

    storeAppendPrintf(sentry, "\tAverage ICP messages per minute since start:\t%.1f\n",
                      stats.avg_icp_messages);

    storeAppendPrintf(sentry, "\tSelect loop called: %.0f times, %0.3f ms avg\n",
                      stats.select_loops, stats.avg_loop_time / fct);

    storeAppendPrintf(sentry, "Cache information for %s:\n",APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tHits as %% of all requests:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      stats.request_hit_ratio5 / fct,
                      stats.request_hit_ratio60 / fct);

    storeAppendPrintf(sentry, "\tHits as %% of bytes sent:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      stats.byte_hit_ratio5 / fct,
                      stats.byte_hit_ratio60 / fct);

    storeAppendPrintf(sentry, "\tMemory hits as %% of hit requests:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      stats.request_hit_mem_ratio5 / fct,
                      stats.request_hit_mem_ratio60 / fct);

    storeAppendPrintf(sentry, "\tDisk hits as %% of hit requests:\t5min: %3.1f%%, 60min: %3.1f%%\n",
                      stats.request_hit_disk_ratio5 / fct,
                      stats.request_hit_disk_ratio60 / fct);

    storeAppendPrintf(sentry, "\tStorage Swap size:\t%.0f KB\n",
                      stats.store.swap.size / 1024);

    storeAppendPrintf(sentry, "\tStorage Swap capacity:\t%4.1f%% used, %4.1f%% free\n",
                      Math::doublePercent(stats.store.swap.size, stats.store.swap.capacity),
                      Math::doublePercent(stats.store.swap.available(), stats.store.swap.capacity));

    storeAppendPrintf(sentry, "\tStorage Mem size:\t%.0f KB\n",
                      stats.store.mem.size / 1024);

    storeAppendPrintf(sentry, "\tStorage Mem capacity:\t%4.1f%% used, %4.1f%% free\n",
                      Math::doublePercent(stats.store.mem.size, stats.store.mem.capacity),
                      Math::doublePercent(stats.store.mem.available(), stats.store.mem.capacity));

    storeAppendPrintf(sentry, "\tMean Object Size:\t%0.2f KB\n",
                      stats.store.swap.meanObjectSize() / 1024);

    storeAppendPrintf(sentry, "\tRequests given to unlinkd:\t%.0f\n",
                      stats.unlink_requests);

    storeAppendPrintf(sentry, "Median Service Times (seconds)  5 min    60 min:\n");

    fct = stats.count > 1 ? stats.count * 1000.0 : 1000.0;
    storeAppendPrintf(sentry, "\tHTTP Requests (All):  %8.5f %8.5f\n",
                      stats.http_requests5 / fct,
                      stats.http_requests60 / fct);

    storeAppendPrintf(sentry, "\tCache Misses:         %8.5f %8.5f\n",
                      stats.cache_misses5 / fct,
                      stats.cache_misses60 / fct);

    storeAppendPrintf(sentry, "\tCache Hits:           %8.5f %8.5f\n",
                      stats.cache_hits5 / fct,
                      stats.cache_hits60 / fct);

    storeAppendPrintf(sentry, "\tNear Hits:            %8.5f %8.5f\n",
                      stats.near_hits5 / fct,
                      stats.near_hits60 / fct);

    storeAppendPrintf(sentry, "\tNot-Modified Replies: %8.5f %8.5f\n",
                      stats.not_modified_replies5 / fct,
                      stats.not_modified_replies60 / fct);

    storeAppendPrintf(sentry, "\tDNS Lookups:          %8.5f %8.5f\n",
                      stats.dns_lookups5 / fct,
                      stats.dns_lookups60 / fct);

    fct = stats.count > 1 ? stats.count * 1000000.0 : 1000000.0;
    storeAppendPrintf(sentry, "\tICP Queries:          %8.5f %8.5f\n",
                      stats.icp_queries5 / fct,
                      stats.icp_queries60 / fct);

    storeAppendPrintf(sentry, "Resource usage for %s:\n", APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tUP Time:\t%.3f seconds\n", stats.up_time);

    storeAppendPrintf(sentry, "\tCPU Time:\t%.3f seconds\n", stats.cpu_time);

    storeAppendPrintf(sentry, "\tCPU Usage:\t%.2f%%\n",
                      stats.cpu_usage);

    storeAppendPrintf(sentry, "\tCPU Usage, 5 minute avg:\t%.2f%%\n",
                      stats.cpu_usage5);

    storeAppendPrintf(sentry, "\tCPU Usage, 60 minute avg:\t%.2f%%\n",
                      stats.cpu_usage60);

    storeAppendPrintf(sentry, "\tMaximum Resident Size: %.0f KB\n",
                      stats.maxrss);

    storeAppendPrintf(sentry, "\tPage faults with physical i/o: %.0f\n",
                      stats.page_faults);

#if HAVE_MSTATS && HAVE_GNUMALLOC_H

    storeAppendPrintf(sentry, "Memory usage for %s via mstats():\n",APP_SHORTNAME);

    storeAppendPrintf(sentry, "\tTotal space in arena:  %6.0f KB\n",
                      stats.ms_bytes_total / 1024);

    storeAppendPrintf(sentry, "\tTotal free:            %6.0f KB %.0f%%\n",
                      stats.ms_bytes_free / 1024,
                      Math::doublePercent(stats.ms_bytes_free, stats.ms_bytes_total));

#endif

    storeAppendPrintf(sentry, "Memory accounted for:\n");
    storeAppendPrintf(sentry, "\tTotal accounted:       %6.0f KB\n",
                      stats.total_accounted / 1024);
    {
        MemPoolGlobalStats mp_stats;
        memPoolGetGlobalStats(&mp_stats);
        storeAppendPrintf(sentry, "\tmemPoolAlloc calls: %9.0f\n",
                          stats.gb_saved_count);
        storeAppendPrintf(sentry, "\tmemPoolFree calls:  %9.0f\n",
                          stats.gb_freed_count);
    }

    storeAppendPrintf(sentry, "File descriptor usage for %s:\n", APP_SHORTNAME);
    storeAppendPrintf(sentry, "\tMaximum number of file descriptors:   %4.0f\n",
                      stats.max_fd);
    storeAppendPrintf(sentry, "\tLargest file desc currently in use:   %4.0f\n",
                      stats.biggest_fd);
    storeAppendPrintf(sentry, "\tNumber of file desc currently in use: %4.0f\n",
                      stats.number_fd);
    storeAppendPrintf(sentry, "\tFiles queued for open:                %4.0f\n",
                      stats.opening_fd);
    storeAppendPrintf(sentry, "\tAvailable number of file descriptors: %4.0f\n",
                      stats.num_fd_free);
    storeAppendPrintf(sentry, "\tReserved number of file descriptors:  %4.0f\n",
                      stats.reserved_fd);
    storeAppendPrintf(sentry, "\tStore Disk files open:                %4.0f\n",
                      stats.store.swap.open_disk_fd);

    storeAppendPrintf(sentry, "Internal Data Structures:\n");
    storeAppendPrintf(sentry, "\t%6.0f StoreEntries\n",
                      stats.store.store_entry_count);
    storeAppendPrintf(sentry, "\t%6.0f StoreEntries with MemObjects\n",
                      stats.store.mem_object_count);
    storeAppendPrintf(sentry, "\t%6.0f Hot Object Cache Items\n",
                      stats.store.mem.count);
    storeAppendPrintf(sentry, "\t%6.0f on-disk objects\n",
                      stats.store.swap.count);
}

void
DumpMallocStatistics(StoreEntry* sentry)
{
#if XMALLOC_STATISTICS
    xm_deltat = current_dtime - xm_time;
    xm_time = current_dtime;
    storeAppendPrintf(sentry, "\nMemory allocation statistics\n");
    storeAppendPrintf(sentry, "%12s %15s %6s %12s\n","Alloc Size","Count","Delta","Alloc/sec");
    malloc_statistics(info_get_mallstat, sentry);
#endif
}

void
GetServiceTimesStats(Mgr::ServiceTimesActionData& stats)
{
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        double p = (i + 1) * 5 / 100.0;
        stats.http_requests5[i] = statPctileSvc(p, 5, PCTILE_HTTP);
        stats.http_requests60[i] = statPctileSvc(p, 60, PCTILE_HTTP);

        stats.cache_misses5[i] = statPctileSvc(p, 5, PCTILE_MISS);
        stats.cache_misses60[i] = statPctileSvc(p, 60, PCTILE_MISS);

        stats.cache_hits5[i] = statPctileSvc(p, 5, PCTILE_HIT);
        stats.cache_hits60[i] = statPctileSvc(p, 60, PCTILE_HIT);

        stats.near_hits5[i] = statPctileSvc(p, 5, PCTILE_NH);
        stats.near_hits60[i] = statPctileSvc(p, 60, PCTILE_NH);

        stats.not_modified_replies5[i] = statPctileSvc(p, 5, PCTILE_NM);
        stats.not_modified_replies60[i] = statPctileSvc(p, 60, PCTILE_NM);

        stats.dns_lookups5[i] = statPctileSvc(p, 5, PCTILE_DNS);
        stats.dns_lookups60[i] = statPctileSvc(p, 60, PCTILE_DNS);

        stats.icp_queries5[i] = statPctileSvc(p, 5, PCTILE_ICP_QUERY);
        stats.icp_queries60[i] = statPctileSvc(p, 60, PCTILE_ICP_QUERY);
    }
}

void
DumpServiceTimesStats(Mgr::ServiceTimesActionData& stats, StoreEntry* sentry)
{
    storeAppendPrintf(sentry, "Service Time Percentiles            5 min    60 min:\n");
    double fct = stats.count > 1 ? stats.count * 1000.0 : 1000.0;
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tHTTP Requests (All):  %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.http_requests5[i] / fct,
                          stats.http_requests60[i] / fct);
    }
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tCache Misses:         %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.cache_misses5[i] / fct,
                          stats.cache_misses60[i] / fct);
    }
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tCache Hits:           %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.cache_hits5[i] / fct,
                          stats.cache_hits60[i] / fct);
    }
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tNear Hits:            %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.near_hits5[i] / fct,
                          stats.near_hits60[i] / fct);
    }
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tNot-Modified Replies: %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.not_modified_replies5[i] / fct,
                          stats.not_modified_replies60[i] / fct);
    }
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tDNS Lookups:          %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.dns_lookups5[i] / fct,
                          stats.dns_lookups60[i] / fct);
    }
    fct = stats.count > 1 ? stats.count * 1000000.0 : 1000000.0;
    for (int i = 0; i < Mgr::ServiceTimesActionData::seriesSize; ++i) {
        storeAppendPrintf(sentry, "\tICP Queries:          %2d%%  %8.5f %8.5f\n",
                          (i + 1) * 5,
                          stats.icp_queries5[i] / fct,
                          stats.icp_queries60[i] / fct);
    }
}

static void
statAvgDump(StoreEntry * sentry, int minutes, int hours)
{
    Mgr::IntervalActionData stats;
    GetAvgStat(stats, minutes, hours);
    DumpAvgStat(stats, sentry);
}

#define XAVG(X) (dt ? (double) (f->X - l->X) / dt : 0.0)
void
GetAvgStat(Mgr::IntervalActionData& stats, int minutes, int hours)
{
    StatCounters *f;
    StatCounters *l;
    double dt;
    double ct;
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
        debugs(18, DBG_IMPORTANT, "statAvgDump: Invalid args, minutes=" << minutes << ", hours=" << hours);
        return;
    }

    dt = tvSubDsec(l->timestamp, f->timestamp);
    ct = f->cputime - l->cputime;

    stats.sample_start_time = l->timestamp;
    stats.sample_end_time = f->timestamp;

    stats.client_http_requests = XAVG(client_http.requests);
    stats.client_http_hits = XAVG(client_http.hits);
    stats.client_http_errors = XAVG(client_http.errors);
    stats.client_http_kbytes_in = XAVG(client_http.kbytes_in.kb);
    stats.client_http_kbytes_out = XAVG(client_http.kbytes_out.kb);

    stats.client_http_all_median_svc_time = statHistDeltaMedian(l->client_http.allSvcTime,
                                            f->client_http.allSvcTime) / 1000.0;
    stats.client_http_miss_median_svc_time = statHistDeltaMedian(l->client_http.missSvcTime,
            f->client_http.missSvcTime) / 1000.0;
    stats.client_http_nm_median_svc_time = statHistDeltaMedian(l->client_http.nearMissSvcTime,
                                           f->client_http.nearMissSvcTime) / 1000.0;
    stats.client_http_nh_median_svc_time = statHistDeltaMedian(l->client_http.nearHitSvcTime,
                                           f->client_http.nearHitSvcTime) / 1000.0;
    stats.client_http_hit_median_svc_time = statHistDeltaMedian(l->client_http.hitSvcTime,
                                            f->client_http.hitSvcTime) / 1000.0;

    stats.server_all_requests = XAVG(server.all.requests);
    stats.server_all_errors = XAVG(server.all.errors);
    stats.server_all_kbytes_in = XAVG(server.all.kbytes_in.kb);
    stats.server_all_kbytes_out = XAVG(server.all.kbytes_out.kb);

    stats.server_http_requests = XAVG(server.http.requests);
    stats.server_http_errors = XAVG(server.http.errors);
    stats.server_http_kbytes_in = XAVG(server.http.kbytes_in.kb);
    stats.server_http_kbytes_out = XAVG(server.http.kbytes_out.kb);

    stats.server_ftp_requests = XAVG(server.ftp.requests);
    stats.server_ftp_errors = XAVG(server.ftp.errors);
    stats.server_ftp_kbytes_in = XAVG(server.ftp.kbytes_in.kb);
    stats.server_ftp_kbytes_out = XAVG(server.ftp.kbytes_out.kb);

    stats.server_other_requests = XAVG(server.other.requests);
    stats.server_other_errors = XAVG(server.other.errors);
    stats.server_other_kbytes_in = XAVG(server.other.kbytes_in.kb);
    stats.server_other_kbytes_out = XAVG(server.other.kbytes_out.kb);

    stats.icp_pkts_sent = XAVG(icp.pkts_sent);
    stats.icp_pkts_recv = XAVG(icp.pkts_recv);
    stats.icp_queries_sent = XAVG(icp.queries_sent);
    stats.icp_replies_sent = XAVG(icp.replies_sent);
    stats.icp_queries_recv = XAVG(icp.queries_recv);
    stats.icp_replies_recv = XAVG(icp.replies_recv);
    stats.icp_replies_queued = XAVG(icp.replies_queued);
    stats.icp_query_timeouts = XAVG(icp.query_timeouts);
    stats.icp_kbytes_sent = XAVG(icp.kbytes_sent.kb);
    stats.icp_kbytes_recv = XAVG(icp.kbytes_recv.kb);
    stats.icp_q_kbytes_sent = XAVG(icp.q_kbytes_sent.kb);
    stats.icp_r_kbytes_sent = XAVG(icp.r_kbytes_sent.kb);
    stats.icp_q_kbytes_recv = XAVG(icp.q_kbytes_recv.kb);
    stats.icp_r_kbytes_recv = XAVG(icp.r_kbytes_recv.kb);

    stats.icp_query_median_svc_time = statHistDeltaMedian(l->icp.querySvcTime,
                                      f->icp.querySvcTime) / 1000000.0;
    stats.icp_reply_median_svc_time = statHistDeltaMedian(l->icp.replySvcTime,
                                      f->icp.replySvcTime) / 1000000.0;
    stats.dns_median_svc_time = statHistDeltaMedian(l->dns.svcTime,
                                f->dns.svcTime) / 1000.0;

    stats.unlink_requests = XAVG(unlink.requests);
    stats.page_faults = XAVG(page_faults);
    stats.select_loops = XAVG(select_loops);
    stats.select_fds = XAVG(select_fds);
    stats.average_select_fd_period = f->select_fds > l->select_fds ?
                                     (f->select_time - l->select_time) / (f->select_fds - l->select_fds) : 0.0;

    stats.median_select_fds = statHistDeltaMedian(l->select_fds_hist, f->select_fds_hist);
    stats.swap_outs = XAVG(swap.outs);
    stats.swap_ins = XAVG(swap.ins);
    stats.swap_files_cleaned = XAVG(swap.files_cleaned);
    stats.aborted_requests = XAVG(aborted_requests);

    stats.syscalls_disk_opens = XAVG(syscalls.disk.opens);
    stats.syscalls_disk_closes = XAVG(syscalls.disk.closes);
    stats.syscalls_disk_reads = XAVG(syscalls.disk.reads);
    stats.syscalls_disk_writes = XAVG(syscalls.disk.writes);
    stats.syscalls_disk_seeks = XAVG(syscalls.disk.seeks);
    stats.syscalls_disk_unlinks = XAVG(syscalls.disk.unlinks);
    stats.syscalls_sock_accepts = XAVG(syscalls.sock.accepts);
    stats.syscalls_sock_sockets = XAVG(syscalls.sock.sockets);
    stats.syscalls_sock_connects = XAVG(syscalls.sock.connects);
    stats.syscalls_sock_binds = XAVG(syscalls.sock.binds);
    stats.syscalls_sock_closes = XAVG(syscalls.sock.closes);
    stats.syscalls_sock_reads = XAVG(syscalls.sock.reads);
    stats.syscalls_sock_writes = XAVG(syscalls.sock.writes);
    stats.syscalls_sock_recvfroms = XAVG(syscalls.sock.recvfroms);
    stats.syscalls_sock_sendtos = XAVG(syscalls.sock.sendtos);
    stats.syscalls_selects = XAVG(syscalls.selects);

    stats.cpu_time = ct;
    stats.wall_time = dt;
}

void
DumpAvgStat(Mgr::IntervalActionData& stats, StoreEntry* sentry)
{
    storeAppendPrintf(sentry, "sample_start_time = %d.%d (%s)\n",
                      (int)stats.sample_start_time.tv_sec,
                      (int)stats.sample_start_time.tv_usec,
                      mkrfc1123(stats.sample_start_time.tv_sec));
    storeAppendPrintf(sentry, "sample_end_time = %d.%d (%s)\n",
                      (int)stats.sample_end_time.tv_sec,
                      (int)stats.sample_end_time.tv_usec,
                      mkrfc1123(stats.sample_end_time.tv_sec));

    storeAppendPrintf(sentry, "client_http.requests = %f/sec\n",
                      stats.client_http_requests);
    storeAppendPrintf(sentry, "client_http.hits = %f/sec\n",
                      stats.client_http_hits);
    storeAppendPrintf(sentry, "client_http.errors = %f/sec\n",
                      stats.client_http_errors);
    storeAppendPrintf(sentry, "client_http.kbytes_in = %f/sec\n",
                      stats.client_http_kbytes_in);
    storeAppendPrintf(sentry, "client_http.kbytes_out = %f/sec\n",
                      stats.client_http_kbytes_out);

    double fct = stats.count > 1 ? stats.count : 1.0;
    storeAppendPrintf(sentry, "client_http.all_median_svc_time = %f seconds\n",
                      stats.client_http_all_median_svc_time / fct);
    storeAppendPrintf(sentry, "client_http.miss_median_svc_time = %f seconds\n",
                      stats.client_http_miss_median_svc_time / fct);
    storeAppendPrintf(sentry, "client_http.nm_median_svc_time = %f seconds\n",
                      stats.client_http_nm_median_svc_time / fct);
    storeAppendPrintf(sentry, "client_http.nh_median_svc_time = %f seconds\n",
                      stats.client_http_nh_median_svc_time / fct);
    storeAppendPrintf(sentry, "client_http.hit_median_svc_time = %f seconds\n",
                      stats.client_http_hit_median_svc_time / fct);

    storeAppendPrintf(sentry, "server.all.requests = %f/sec\n",
                      stats.server_all_requests);
    storeAppendPrintf(sentry, "server.all.errors = %f/sec\n",
                      stats.server_all_errors);
    storeAppendPrintf(sentry, "server.all.kbytes_in = %f/sec\n",
                      stats.server_all_kbytes_in);
    storeAppendPrintf(sentry, "server.all.kbytes_out = %f/sec\n",
                      stats.server_all_kbytes_out);

    storeAppendPrintf(sentry, "server.http.requests = %f/sec\n",
                      stats.server_http_requests);
    storeAppendPrintf(sentry, "server.http.errors = %f/sec\n",
                      stats.server_http_errors);
    storeAppendPrintf(sentry, "server.http.kbytes_in = %f/sec\n",
                      stats.server_http_kbytes_in);
    storeAppendPrintf(sentry, "server.http.kbytes_out = %f/sec\n",
                      stats.server_http_kbytes_out);

    storeAppendPrintf(sentry, "server.ftp.requests = %f/sec\n",
                      stats.server_ftp_requests);
    storeAppendPrintf(sentry, "server.ftp.errors = %f/sec\n",
                      stats.server_ftp_errors);
    storeAppendPrintf(sentry, "server.ftp.kbytes_in = %f/sec\n",
                      stats.server_ftp_kbytes_in);
    storeAppendPrintf(sentry, "server.ftp.kbytes_out = %f/sec\n",
                      stats.server_ftp_kbytes_out);

    storeAppendPrintf(sentry, "server.other.requests = %f/sec\n",
                      stats.server_other_requests);
    storeAppendPrintf(sentry, "server.other.errors = %f/sec\n",
                      stats.server_other_errors);
    storeAppendPrintf(sentry, "server.other.kbytes_in = %f/sec\n",
                      stats.server_other_kbytes_in);
    storeAppendPrintf(sentry, "server.other.kbytes_out = %f/sec\n",
                      stats.server_other_kbytes_out);

    storeAppendPrintf(sentry, "icp.pkts_sent = %f/sec\n",
                      stats.icp_pkts_sent);
    storeAppendPrintf(sentry, "icp.pkts_recv = %f/sec\n",
                      stats.icp_pkts_recv);
    storeAppendPrintf(sentry, "icp.queries_sent = %f/sec\n",
                      stats.icp_queries_sent);
    storeAppendPrintf(sentry, "icp.replies_sent = %f/sec\n",
                      stats.icp_replies_sent);
    storeAppendPrintf(sentry, "icp.queries_recv = %f/sec\n",
                      stats.icp_queries_recv);
    storeAppendPrintf(sentry, "icp.replies_recv = %f/sec\n",
                      stats.icp_replies_recv);
    storeAppendPrintf(sentry, "icp.replies_queued = %f/sec\n",
                      stats.icp_replies_queued);
    storeAppendPrintf(sentry, "icp.query_timeouts = %f/sec\n",
                      stats.icp_query_timeouts);
    storeAppendPrintf(sentry, "icp.kbytes_sent = %f/sec\n",
                      stats.icp_kbytes_sent);
    storeAppendPrintf(sentry, "icp.kbytes_recv = %f/sec\n",
                      stats.icp_kbytes_recv);
    storeAppendPrintf(sentry, "icp.q_kbytes_sent = %f/sec\n",
                      stats.icp_q_kbytes_sent);
    storeAppendPrintf(sentry, "icp.r_kbytes_sent = %f/sec\n",
                      stats.icp_r_kbytes_sent);
    storeAppendPrintf(sentry, "icp.q_kbytes_recv = %f/sec\n",
                      stats.icp_q_kbytes_recv);
    storeAppendPrintf(sentry, "icp.r_kbytes_recv = %f/sec\n",
                      stats.icp_r_kbytes_recv);
    storeAppendPrintf(sentry, "icp.query_median_svc_time = %f seconds\n",
                      stats.icp_query_median_svc_time / fct);
    storeAppendPrintf(sentry, "icp.reply_median_svc_time = %f seconds\n",
                      stats.icp_reply_median_svc_time / fct);
    storeAppendPrintf(sentry, "dns.median_svc_time = %f seconds\n",
                      stats.dns_median_svc_time / fct);
    storeAppendPrintf(sentry, "unlink.requests = %f/sec\n",
                      stats.unlink_requests);
    storeAppendPrintf(sentry, "page_faults = %f/sec\n",
                      stats.page_faults);
    storeAppendPrintf(sentry, "select_loops = %f/sec\n",
                      stats.select_loops);
    storeAppendPrintf(sentry, "select_fds = %f/sec\n",
                      stats.select_fds);
    storeAppendPrintf(sentry, "average_select_fd_period = %f/fd\n",
                      stats.average_select_fd_period / fct);
    storeAppendPrintf(sentry, "median_select_fds = %f\n",
                      stats.median_select_fds / fct);
    storeAppendPrintf(sentry, "swap.outs = %f/sec\n",
                      stats.swap_outs);
    storeAppendPrintf(sentry, "swap.ins = %f/sec\n",
                      stats.swap_ins);
    storeAppendPrintf(sentry, "swap.files_cleaned = %f/sec\n",
                      stats.swap_files_cleaned);
    storeAppendPrintf(sentry, "aborted_requests = %f/sec\n",
                      stats.aborted_requests);

#if USE_POLL
    storeAppendPrintf(sentry, "syscalls.polls = %f/sec\n", stats.syscalls_selects);
#elif defined(USE_SELECT) || defined(USE_SELECT_WIN32)
    storeAppendPrintf(sentry, "syscalls.selects = %f/sec\n", stats.syscalls_selects);
#endif

    storeAppendPrintf(sentry, "syscalls.disk.opens = %f/sec\n", stats.syscalls_disk_opens);
    storeAppendPrintf(sentry, "syscalls.disk.closes = %f/sec\n", stats.syscalls_disk_closes);
    storeAppendPrintf(sentry, "syscalls.disk.reads = %f/sec\n", stats.syscalls_disk_reads);
    storeAppendPrintf(sentry, "syscalls.disk.writes = %f/sec\n", stats.syscalls_disk_writes);
    storeAppendPrintf(sentry, "syscalls.disk.seeks = %f/sec\n", stats.syscalls_disk_seeks);
    storeAppendPrintf(sentry, "syscalls.disk.unlinks = %f/sec\n", stats.syscalls_disk_unlinks);
    storeAppendPrintf(sentry, "syscalls.sock.accepts = %f/sec\n", stats.syscalls_sock_accepts);
    storeAppendPrintf(sentry, "syscalls.sock.sockets = %f/sec\n", stats.syscalls_sock_sockets);
    storeAppendPrintf(sentry, "syscalls.sock.connects = %f/sec\n", stats.syscalls_sock_connects);
    storeAppendPrintf(sentry, "syscalls.sock.binds = %f/sec\n", stats.syscalls_sock_binds);
    storeAppendPrintf(sentry, "syscalls.sock.closes = %f/sec\n", stats.syscalls_sock_closes);
    storeAppendPrintf(sentry, "syscalls.sock.reads = %f/sec\n", stats.syscalls_sock_reads);
    storeAppendPrintf(sentry, "syscalls.sock.writes = %f/sec\n", stats.syscalls_sock_writes);
    storeAppendPrintf(sentry, "syscalls.sock.recvfroms = %f/sec\n", stats.syscalls_sock_recvfroms);
    storeAppendPrintf(sentry, "syscalls.sock.sendtos = %f/sec\n", stats.syscalls_sock_sendtos);

    storeAppendPrintf(sentry, "cpu_time = %f seconds\n", stats.cpu_time);
    storeAppendPrintf(sentry, "wall_time = %f seconds\n", stats.wall_time);
    storeAppendPrintf(sentry, "cpu_usage = %f%%\n", Math::doublePercent(stats.cpu_time, stats.wall_time));
}

static void
statRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("info", "General Runtime Information",
                        &Mgr::InfoAction::Create, 0, 1);
    Mgr::RegisterAction("service_times", "Service Times (Percentiles)",
                        &Mgr::ServiceTimesAction::Create, 0, 1);
    Mgr::RegisterAction("filedescriptors", "Process Filedescriptor Allocation",
                        fde::DumpStats, 0, 1);
    Mgr::RegisterAction("objects", "All Cache Objects", stat_objects_get, 0, 0);
    Mgr::RegisterAction("vm_objects", "In-Memory and In-Transit Objects",
                        stat_vmobjects_get, 0, 0);
    Mgr::RegisterAction("io", "Server-side network read() size histograms",
                        &Mgr::IoAction::Create, 0, 1);
    Mgr::RegisterAction("counters", "Traffic and Resource Counters",
                        &Mgr::CountersAction::Create, 0, 1);
    Mgr::RegisterAction("peer_select", "Peer Selection Algorithms",
                        statPeerSelect, 0, 1);
    Mgr::RegisterAction("digest_stats", "Cache Digest and ICP blob",
                        statDigestBlob, 0, 1);
    Mgr::RegisterAction("5min", "5 Minute Average of Counters",
                        &Mgr::IntervalAction::Create5min, 0, 1);
    Mgr::RegisterAction("60min", "60 Minute Average of Counters",
                        &Mgr::IntervalAction::Create60min, 0, 1);
    Mgr::RegisterAction("utilization", "Cache Utilization",
                        statUtilization, 0, 1);
    Mgr::RegisterAction("histograms", "Full Histogram Counts",
                        statCountersHistograms, 0, 1);
    Mgr::RegisterAction("active_requests",
                        "Client-side Active Requests",
                        statClientRequests, 0, 1);
#if USE_AUTH
    Mgr::RegisterAction("username_cache",
                        "Active Cached Usernames",
                        Auth::User::CredentialsCacheStats, 0, 1);
#endif
#if DEBUG_OPENFD
    Mgr::RegisterAction("openfd_objects", "Objects with Swapout files open",
                        statOpenfdObj, 0, 0);
#endif
#if STAT_GRAPHS
    Mgr::RegisterAction("graph_variables", "Display cache metrics graphically",
                        statGraphDump, 0, 1);
#endif
}

/* add special cases here as they arrive */
static void
statCountersInitSpecial(StatCounters * C)
{
    /*
     * HTTP svc_time hist is kept in milli-seconds; max of 3 hours.
     */
    C->client_http.allSvcTime.logInit(300, 0.0, 3600000.0 * 3.0);
    C->client_http.missSvcTime.logInit(300, 0.0, 3600000.0 * 3.0);
    C->client_http.nearMissSvcTime.logInit(300, 0.0, 3600000.0 * 3.0);
    C->client_http.nearHitSvcTime.logInit(300, 0.0, 3600000.0 * 3.0);
    C->client_http.hitSvcTime.logInit(300, 0.0, 3600000.0 * 3.0);
    /*
     * ICP svc_time hist is kept in micro-seconds; max of 1 minute.
     */
    C->icp.querySvcTime.logInit(300, 0.0, 1000000.0 * 60.0);
    C->icp.replySvcTime.logInit(300, 0.0, 1000000.0 * 60.0);
    /*
     * DNS svc_time hist is kept in milli-seconds; max of 10 minutes.
     */
    C->dns.svcTime.logInit(300, 0.0, 60000.0 * 10.0);
    /*
     * Cache Digest Stuff
     */
    C->cd.on_xition_count.enumInit(CacheDigestHashFuncCount);
    C->comm_udp_incoming.enumInit(INCOMING_UDP_MAX);
    C->comm_dns_incoming.enumInit(INCOMING_DNS_MAX);
    C->comm_tcp_incoming.enumInit(INCOMING_TCP_MAX);
    C->select_fds_hist.enumInit(256);   /* was SQUID_MAXFD, but it is way too much. It is OK to crop this statistics */
}

static void
statCountersInit(StatCounters * C)
{
    assert(C);
    *C = StatCounters();
    statCountersInitSpecial(C);
}

void
statInit(void)
{
    int i;
    debugs(18, 5, "statInit: Initializing...");

    for (i = 0; i < N_COUNT_HIST; ++i)
        statCountersInit(&CountHist[i]);

    for (i = 0; i < N_COUNT_HOUR_HIST; ++i)
        statCountersInit(&CountHourHist[i]);

    statCountersInit(&statCounter);

    eventAdd("statAvgTick", statAvgTick, NULL, (double) COUNT_INTERVAL, 1);

    ClientActiveRequests.head = NULL;

    ClientActiveRequests.tail = NULL;

    statRegisterWithCacheManager();
}

static void
statAvgTick(void *)
{
    struct rusage rusage;
    eventAdd("statAvgTick", statAvgTick, NULL, (double) COUNT_INTERVAL, 1);
    squid_getrusage(&rusage);
    statCounter.page_faults = rusage_pagefaults(&rusage);
    statCounter.cputime = rusage_cputime(&rusage);
    statCounter.timestamp = current_time;
    // shift all elements right and prepend statCounter
    for(int i = N_COUNT_HIST-1; i > 0; --i)
        CountHist[i] = CountHist[i-1];
    CountHist[0] = statCounter;
    ++NCountHist;

    if ((NCountHist % COUNT_INTERVAL) == 0) {
        /* we have an hours worth of readings.  store previous hour */
        // shift all elements right and prepend final CountHist element
        for(int i = N_COUNT_HOUR_HIST-1; i > 0; --i)
            CountHourHist[i] = CountHourHist[i-1];
        CountHourHist[0] = CountHist[N_COUNT_HIST - 1];
        ++NCountHourHist;
    }

    if (Config.warnings.high_rptm > 0) {
        int i = (int) statPctileSvc(0.5, 20, PCTILE_HTTP);

        if (Config.warnings.high_rptm < i)
            debugs(18, DBG_CRITICAL, "WARNING: Median response time is " << i << " milliseconds");
    }

    if (Config.warnings.high_pf) {
        int i = (CountHist[0].page_faults - CountHist[1].page_faults);
        double dt = tvSubDsec(CountHist[0].timestamp, CountHist[1].timestamp);

        if (i > 0 && dt > 0.0) {
            i /= (int) dt;

            if (Config.warnings.high_pf < i)
                debugs(18, DBG_CRITICAL, "WARNING: Page faults occurring at " << i << "/sec");
        }
    }

    if (Config.warnings.high_memory) {
        size_t i = 0;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
        struct mstats ms = mstats();
        i = ms.bytes_total;
#endif
        if (Config.warnings.high_memory < i)
            debugs(18, DBG_CRITICAL, "WARNING: Memory usage at " << ((unsigned long int)(i >> 20)) << " MB");
    }
}

static void
statCountersHistograms(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "client_http.allSvcTime histogram:\n");
    statCounter.client_http.allSvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "client_http.missSvcTime histogram:\n");
    statCounter.client_http.missSvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "client_http.nearMissSvcTime histogram:\n");
    statCounter.client_http.nearMissSvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "client_http.nearHitSvcTime histogram:\n");
    statCounter.client_http.nearHitSvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "client_http.hitSvcTime histogram:\n");
    statCounter.client_http.hitSvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "icp.querySvcTime histogram:\n");
    statCounter.icp.querySvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "icp.replySvcTime histogram:\n");
    statCounter.icp.replySvcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "dns.svc_time histogram:\n");
    statCounter.dns.svcTime.dump(sentry, NULL);
    storeAppendPrintf(sentry, "select_fds_hist histogram:\n");
    statCounter.select_fds_hist.dump(sentry, NULL);
}

static void
statCountersDump(StoreEntry * sentry)
{
    Mgr::CountersActionData stats;
    GetCountersStats(stats);
    DumpCountersStats(stats, sentry);
}

void
GetCountersStats(Mgr::CountersActionData& stats)
{
    StatCounters *f = &statCounter;

    struct rusage rusage;
    squid_getrusage(&rusage);
    f->page_faults = rusage_pagefaults(&rusage);
    f->cputime = rusage_cputime(&rusage);

    stats.sample_time = f->timestamp;
    stats.client_http_requests = f->client_http.requests;
    stats.client_http_hits = f->client_http.hits;
    stats.client_http_errors = f->client_http.errors;
    stats.client_http_kbytes_in = f->client_http.kbytes_in.kb;
    stats.client_http_kbytes_out = f->client_http.kbytes_out.kb;
    stats.client_http_hit_kbytes_out = f->client_http.hit_kbytes_out.kb;

    stats.server_all_requests = f->server.all.requests;
    stats.server_all_errors = f->server.all.errors;
    stats.server_all_kbytes_in = f->server.all.kbytes_in.kb;
    stats.server_all_kbytes_out = f->server.all.kbytes_out.kb;

    stats.server_http_requests = f->server.http.requests;
    stats.server_http_errors = f->server.http.errors;
    stats.server_http_kbytes_in = f->server.http.kbytes_in.kb;
    stats.server_http_kbytes_out = f->server.http.kbytes_out.kb;

    stats.server_ftp_requests = f->server.ftp.requests;
    stats.server_ftp_errors = f->server.ftp.errors;
    stats.server_ftp_kbytes_in = f->server.ftp.kbytes_in.kb;
    stats.server_ftp_kbytes_out = f->server.ftp.kbytes_out.kb;

    stats.server_other_requests = f->server.other.requests;
    stats.server_other_errors = f->server.other.errors;
    stats.server_other_kbytes_in = f->server.other.kbytes_in.kb;
    stats.server_other_kbytes_out = f->server.other.kbytes_out.kb;

    stats.icp_pkts_sent = f->icp.pkts_sent;
    stats.icp_pkts_recv = f->icp.pkts_recv;
    stats.icp_queries_sent = f->icp.queries_sent;
    stats.icp_replies_sent = f->icp.replies_sent;
    stats.icp_queries_recv = f->icp.queries_recv;
    stats.icp_replies_recv = f->icp.replies_recv;
    stats.icp_query_timeouts = f->icp.query_timeouts;
    stats.icp_replies_queued = f->icp.replies_queued;
    stats.icp_kbytes_sent = f->icp.kbytes_sent.kb;
    stats.icp_kbytes_recv = f->icp.kbytes_recv.kb;
    stats.icp_q_kbytes_sent = f->icp.q_kbytes_sent.kb;
    stats.icp_r_kbytes_sent = f->icp.r_kbytes_sent.kb;
    stats.icp_q_kbytes_recv = f->icp.q_kbytes_recv.kb;
    stats.icp_r_kbytes_recv = f->icp.r_kbytes_recv.kb;

#if USE_CACHE_DIGESTS

    stats.icp_times_used = f->icp.times_used;
    stats.cd_times_used = f->cd.times_used;
    stats.cd_msgs_sent = f->cd.msgs_sent;
    stats.cd_msgs_recv = f->cd.msgs_recv;
    stats.cd_memory = f->cd.memory.kb;
    stats.cd_local_memory = store_digest ? store_digest->mask_size / 1024 : 0;
    stats.cd_kbytes_sent = f->cd.kbytes_sent.kb;
    stats.cd_kbytes_recv = f->cd.kbytes_recv.kb;
#endif

    stats.unlink_requests = f->unlink.requests;
    stats.page_faults = f->page_faults;
    stats.select_loops = f->select_loops;
    stats.cpu_time = f->cputime;
    stats.wall_time = tvSubDsec(f->timestamp, current_time);
    stats.swap_outs = f->swap.outs;
    stats.swap_ins = f->swap.ins;
    stats.swap_files_cleaned = f->swap.files_cleaned;
    stats.aborted_requests = f->aborted_requests;
}

void
DumpCountersStats(Mgr::CountersActionData& stats, StoreEntry* sentry)
{
    storeAppendPrintf(sentry, "sample_time = %d.%d (%s)\n",
                      (int) stats.sample_time.tv_sec,
                      (int) stats.sample_time.tv_usec,
                      mkrfc1123(stats.sample_time.tv_sec));
    storeAppendPrintf(sentry, "client_http.requests = %.0f\n",
                      stats.client_http_requests);
    storeAppendPrintf(sentry, "client_http.hits = %.0f\n",
                      stats.client_http_hits);
    storeAppendPrintf(sentry, "client_http.errors = %.0f\n",
                      stats.client_http_errors);
    storeAppendPrintf(sentry, "client_http.kbytes_in = %.0f\n",
                      stats.client_http_kbytes_in);
    storeAppendPrintf(sentry, "client_http.kbytes_out = %.0f\n",
                      stats.client_http_kbytes_out);
    storeAppendPrintf(sentry, "client_http.hit_kbytes_out = %.0f\n",
                      stats.client_http_hit_kbytes_out);

    storeAppendPrintf(sentry, "server.all.requests = %.0f\n",
                      stats.server_all_requests);
    storeAppendPrintf(sentry, "server.all.errors = %.0f\n",
                      stats.server_all_errors);
    storeAppendPrintf(sentry, "server.all.kbytes_in = %.0f\n",
                      stats.server_all_kbytes_in);
    storeAppendPrintf(sentry, "server.all.kbytes_out = %.0f\n",
                      stats.server_all_kbytes_out);

    storeAppendPrintf(sentry, "server.http.requests = %.0f\n",
                      stats.server_http_requests);
    storeAppendPrintf(sentry, "server.http.errors = %.0f\n",
                      stats.server_http_errors);
    storeAppendPrintf(sentry, "server.http.kbytes_in = %.0f\n",
                      stats.server_http_kbytes_in);
    storeAppendPrintf(sentry, "server.http.kbytes_out = %.0f\n",
                      stats.server_http_kbytes_out);

    storeAppendPrintf(sentry, "server.ftp.requests = %.0f\n",
                      stats.server_ftp_requests);
    storeAppendPrintf(sentry, "server.ftp.errors = %.0f\n",
                      stats.server_ftp_errors);
    storeAppendPrintf(sentry, "server.ftp.kbytes_in = %.0f\n",
                      stats.server_ftp_kbytes_in);
    storeAppendPrintf(sentry, "server.ftp.kbytes_out = %.0f\n",
                      stats.server_ftp_kbytes_out);

    storeAppendPrintf(sentry, "server.other.requests = %.0f\n",
                      stats.server_other_requests);
    storeAppendPrintf(sentry, "server.other.errors = %.0f\n",
                      stats.server_other_errors);
    storeAppendPrintf(sentry, "server.other.kbytes_in = %.0f\n",
                      stats.server_other_kbytes_in);
    storeAppendPrintf(sentry, "server.other.kbytes_out = %.0f\n",
                      stats.server_other_kbytes_out);

    storeAppendPrintf(sentry, "icp.pkts_sent = %.0f\n",
                      stats.icp_pkts_sent);
    storeAppendPrintf(sentry, "icp.pkts_recv = %.0f\n",
                      stats.icp_pkts_recv);
    storeAppendPrintf(sentry, "icp.queries_sent = %.0f\n",
                      stats.icp_queries_sent);
    storeAppendPrintf(sentry, "icp.replies_sent = %.0f\n",
                      stats.icp_replies_sent);
    storeAppendPrintf(sentry, "icp.queries_recv = %.0f\n",
                      stats.icp_queries_recv);
    storeAppendPrintf(sentry, "icp.replies_recv = %.0f\n",
                      stats.icp_replies_recv);
    storeAppendPrintf(sentry, "icp.query_timeouts = %.0f\n",
                      stats.icp_query_timeouts);
    storeAppendPrintf(sentry, "icp.replies_queued = %.0f\n",
                      stats.icp_replies_queued);
    storeAppendPrintf(sentry, "icp.kbytes_sent = %.0f\n",
                      stats.icp_kbytes_sent);
    storeAppendPrintf(sentry, "icp.kbytes_recv = %.0f\n",
                      stats.icp_kbytes_recv);
    storeAppendPrintf(sentry, "icp.q_kbytes_sent = %.0f\n",
                      stats.icp_q_kbytes_sent);
    storeAppendPrintf(sentry, "icp.r_kbytes_sent = %.0f\n",
                      stats.icp_r_kbytes_sent);
    storeAppendPrintf(sentry, "icp.q_kbytes_recv = %.0f\n",
                      stats.icp_q_kbytes_recv);
    storeAppendPrintf(sentry, "icp.r_kbytes_recv = %.0f\n",
                      stats.icp_r_kbytes_recv);

#if USE_CACHE_DIGESTS

    storeAppendPrintf(sentry, "icp.times_used = %.0f\n",
                      stats.icp_times_used);
    storeAppendPrintf(sentry, "cd.times_used = %.0f\n",
                      stats.cd_times_used);
    storeAppendPrintf(sentry, "cd.msgs_sent = %.0f\n",
                      stats.cd_msgs_sent);
    storeAppendPrintf(sentry, "cd.msgs_recv = %.0f\n",
                      stats.cd_msgs_recv);
    storeAppendPrintf(sentry, "cd.memory = %.0f\n",
                      stats.cd_memory);
    storeAppendPrintf(sentry, "cd.local_memory = %.0f\n",
                      stats.cd_local_memory);
    storeAppendPrintf(sentry, "cd.kbytes_sent = %.0f\n",
                      stats.cd_kbytes_sent);
    storeAppendPrintf(sentry, "cd.kbytes_recv = %.0f\n",
                      stats.cd_kbytes_recv);
#endif

    storeAppendPrintf(sentry, "unlink.requests = %.0f\n",
                      stats.unlink_requests);
    storeAppendPrintf(sentry, "page_faults = %.0f\n",
                      stats.page_faults);
    storeAppendPrintf(sentry, "select_loops = %.0f\n",
                      stats.select_loops);
    storeAppendPrintf(sentry, "cpu_time = %f\n",
                      stats.cpu_time);
    storeAppendPrintf(sentry, "wall_time = %f\n",
                      stats.wall_time);
    storeAppendPrintf(sentry, "swap.outs = %.0f\n",
                      stats.swap_outs);
    storeAppendPrintf(sentry, "swap.ins = %.0f\n",
                      stats.swap_ins);
    storeAppendPrintf(sentry, "swap.files_cleaned = %.0f\n",
                      stats.swap_files_cleaned);
    storeAppendPrintf(sentry, "aborted_requests = %.0f\n",
                      stats.aborted_requests);
}

void
statFreeMemory(void)
{
    // TODO: replace with delete[]
    for (int i = 0; i < N_COUNT_HIST; ++i)
        CountHist[i] = StatCounters();

    for (int i = 0; i < N_COUNT_HOUR_HIST; ++i)
        CountHourHist[i] = StatCounters();
}

static void
statPeerSelect(StoreEntry * sentry)
{
#if USE_CACHE_DIGESTS
    StatCounters *f = &statCounter;
    CachePeer *peer;
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
        x = statHistDeltaPctile(l->client_http.allSvcTime,f->client_http.allSvcTime, pctile);
        break;

    case PCTILE_HIT:
        x = statHistDeltaPctile(l->client_http.hitSvcTime,f->client_http.hitSvcTime, pctile);
        break;

    case PCTILE_MISS:
        x = statHistDeltaPctile(l->client_http.missSvcTime,f->client_http.missSvcTime, pctile);
        break;

    case PCTILE_NM:
        x = statHistDeltaPctile(l->client_http.nearMissSvcTime,f->client_http.nearMissSvcTime, pctile);
        break;

    case PCTILE_NH:
        x = statHistDeltaPctile(l->client_http.nearHitSvcTime,f->client_http.nearHitSvcTime, pctile);
        break;

    case PCTILE_ICP_QUERY:
        x = statHistDeltaPctile(l->icp.querySvcTime,f->icp.querySvcTime, pctile);
        break;

    case PCTILE_DNS:
        x = statHistDeltaPctile(l->dns.svcTime,f->dns.svcTime, pctile);
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

double
statRequestHitRatio(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].client_http.hits -
                               CountHist[minutes].client_http.hits,
                               CountHist[0].client_http.requests -
                               CountHist[minutes].client_http.requests);
}

double
statRequestHitMemoryRatio(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].client_http.mem_hits -
                               CountHist[minutes].client_http.mem_hits,
                               CountHist[0].client_http.hits -
                               CountHist[minutes].client_http.hits);
}

double
statRequestHitDiskRatio(int minutes)
{
    assert(minutes < N_COUNT_HIST);
    return Math::doublePercent(CountHist[0].client_http.disk_hits -
                               CountHist[minutes].client_http.disk_hits,
                               CountHist[0].client_http.hits -
                               CountHist[minutes].client_http.hits);
}

double
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
        debugs(18, DBG_IMPORTANT, "STRANGE: srv_kbytes=" << s << ", cd_kbytes=" << cd);

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
    char buf[MAX_IPSTRLEN];

    for (i = ClientActiveRequests.head; i; i = i->next) {
        const char *p = NULL;
        http = static_cast<ClientHttpRequest *>(i->data);
        assert(http);
        ConnStateData * conn = http->getConn();
        storeAppendPrintf(s, "Connection: %p\n", conn);

        if (conn != NULL) {
            const int fd = conn->clientConnection->fd;
            storeAppendPrintf(s, "\tFD %d, read %" PRId64 ", wrote %" PRId64 "\n", fd,
                              fd_table[fd].bytes_read, fd_table[fd].bytes_written);
            storeAppendPrintf(s, "\tFD desc: %s\n", fd_table[fd].desc);
            storeAppendPrintf(s, "\tin: buf %p, used %ld, free %ld\n",
                              conn->inBuf.rawContent(), (long int) conn->inBuf.length(), (long int) conn->inBuf.spaceSize());
            storeAppendPrintf(s, "\tremote: %s\n",
                              conn->clientConnection->remote.toUrl(buf,MAX_IPSTRLEN));
            storeAppendPrintf(s, "\tlocal: %s\n",
                              conn->clientConnection->local.toUrl(buf,MAX_IPSTRLEN));
            storeAppendPrintf(s, "\tnrequests: %u\n", conn->pipeline.nrequests);
        }

        storeAppendPrintf(s, "uri %s\n", http->uri);
        storeAppendPrintf(s, "logType %s\n", http->logType.c_str());
        storeAppendPrintf(s, "out.offset %ld, out.size %lu\n",
                          (long int) http->out.offset, (unsigned long int) http->out.size);
        storeAppendPrintf(s, "req_sz %ld\n", (long int) http->req_sz);
        e = http->storeEntry();
        storeAppendPrintf(s, "entry %p/%s\n", e, e ? e->getMD5Text() : "N/A");
        storeAppendPrintf(s, "start %ld.%06d (%f seconds ago)\n",
                          (long int) http->al->cache.start_time.tv_sec,
                          (int) http->al->cache.start_time.tv_usec,
                          tvSubDsec(http->al->cache.start_time, current_time));
#if USE_AUTH
        if (http->request->auth_user_request != NULL)
            p = http->request->auth_user_request->username();
        else
#endif
            if (http->request->extacl_user.size() > 0) {
                p = http->request->extacl_user.termedBuf();
            }

        if (!p && conn != NULL && conn->clientConnection->rfc931[0])
            p = conn->clientConnection->rfc931;

#if USE_OPENSSL
        if (!p && conn != NULL && Comm::IsConnOpen(conn->clientConnection))
            p = sslGetUserEmail(fd_table[conn->clientConnection->fd].ssl.get());
#endif

        if (!p)
            p = dash_str;

        storeAppendPrintf(s, "username %s\n", p);

#if USE_DELAY_POOLS
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
    for (i=0;i<(N_COUNT_HIST-2);++i) { \
    dt = tvSubDsec(CountHist[i+1].timestamp, CountHist[i].timestamp); \
    if (dt <= 0.0) \
        break; \
    storeAppendPrintf(e, "%lu,%0.2f:", \
        CountHist[i].timestamp.tv_sec, \
        ((CountHist[i].Y - CountHist[i+1].Y) / dt)); \
    }

#define GRAPH_PER_HOUR(Y) \
    for (i=0;i<(N_COUNT_HOUR_HIST-2);++i) { \
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

int
statMemoryAccounted(void)
{
    return memPoolsTotalAllocated();
}

