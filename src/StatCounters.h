/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STATCOUNTERS_H
#define SQUID_SRC_STATCOUNTERS_H

#include "base/ByteCounter.h"
#include "comm/Incoming.h"
#include "StatHist.h"

#if USE_CACHE_DIGESTS
/** statistics for cache digests and other hit "predictors" */
class CacheDigestGuessStats
{
public:
    int trueHits = 0;
    int falseHits = 0;
    int trueMisses = 0;
    int falseMisses = 0;
};
#endif

/** General collection of process-wide statistics.
 *
 * \note if you add a field to StatCounters which requires any non-trivial
 *  initialization or copy you MUST sync statCountersInitSpecial()
 */
class StatCounters
{
public:
    StatCounters() : timestamp(current_time) {}

    struct {
        int clients = 0;
        int requests = 0;
        int hits = 0;
        int mem_hits = 0;
        int disk_hits = 0;
        int errors = 0;
        ByteCounter kbytes_in;
        ByteCounter kbytes_out;
        ByteCounter hit_kbytes_out;
        StatHist missSvcTime;
        StatHist nearMissSvcTime;
        StatHist nearHitSvcTime;
        StatHist hitSvcTime;
        StatHist allSvcTime;
    } client_http;

    struct {

        struct {
            int requests = 0;
            int errors = 0;
            ByteCounter kbytes_in;
            ByteCounter kbytes_out;
        } all, http, ftp, other;
    } server;

    struct {
        int pkts_sent = 0;
        int queries_sent = 0;
        int replies_sent = 0;
        int pkts_recv = 0;
        int queries_recv = 0;
        int replies_recv = 0;
        int hits_sent = 0;
        int hits_recv = 0;
        int replies_queued = 0;
        int replies_dropped = 0;
        ByteCounter kbytes_sent;
        ByteCounter q_kbytes_sent;
        ByteCounter r_kbytes_sent;
        ByteCounter kbytes_recv;
        ByteCounter q_kbytes_recv;
        ByteCounter r_kbytes_recv;
        StatHist querySvcTime;
        StatHist replySvcTime;
        int query_timeouts = 0;
        int times_used = 0;
    } icp;

    struct {
        int pkts_sent = 0;
        int pkts_recv = 0;
    } htcp;

    struct {
        int requests = 0;
    } unlink;

    struct {
        StatHist svcTime;
    } dns;

    struct {
        int times_used = 0;
        ByteCounter kbytes_sent;
        ByteCounter kbytes_recv;
        ByteCounter memory;
        int msgs_sent = 0;
        int msgs_recv = 0;
#if USE_CACHE_DIGESTS
        CacheDigestGuessStats guess;
#endif
        StatHist on_xition_count;
    } cd;

    struct {
        int times_used = 0;
    } netdb;
    int page_faults = 0;
    unsigned long int select_loops = 0;
    int select_fds = 0;
    double select_time = 0.0;
    double cputime = 0.0;

    struct timeval timestamp;
#if USE_POLL || USE_SELECT
    Comm::Incoming comm_dns;
    Comm::Incoming comm_tcp;
    Comm::Incoming comm_udp;
#endif
    StatHist select_fds_hist;

    struct {
        struct {
            int opens = 0;
            int closes = 0;
            int reads = 0;
            int writes = 0;
            int seeks = 0;
            int unlinks = 0;
        } disk;

        struct {
            int accepts = 0;
            int sockets = 0;
            int connects = 0;
            int binds = 0;
            int closes = 0;
            int reads = 0;
            int writes = 0;
            int recvfroms = 0;
            int sendtos = 0;
        } sock;
        int selects = 0;
    } syscalls;
    int aborted_requests = 0;

    struct {
        int files_cleaned = 0;
        int outs = 0;
        int ins = 0;
    } swap;

    struct {
        uint64_t attempts = 0;
        uint64_t refusalsDueToLocking = 0;
        uint64_t refusalsDueToZeroSize = 0;
        uint64_t refusalsDueToTimeLimit = 0;
        uint64_t failures = 0;
    } hitValidation;

};

extern StatCounters statCounter;

#endif /* SQUID_SRC_STATCOUNTERS_H */

