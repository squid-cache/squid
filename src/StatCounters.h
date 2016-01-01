/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef STATCOUNTERS_H_
#define STATCOUNTERS_H_

#include "base/ByteCounter.h"
#include "StatHist.h"

#if USE_CACHE_DIGESTS
/** statistics for cache digests and other hit "predictors" */
class CacheDigestGuessStats
{
public:
    int trueHits;
    int falseHits;
    int trueMisses;
    int falseMisses;
    int closeHits;     /// \todo: temporary remove it later
};
#endif

/** General collection of process-wide statistics.
 *
 * \note if you add a field to StatCounters,
 * you MUST sync statCountersInitSpecial, statCountersClean, and statCountersCopy
 */
class StatCounters
{
public:
    struct {
        int clients;
        int requests;
        int hits;
        int mem_hits;
        int disk_hits;
        int errors;
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
            int requests;
            int errors;
            ByteCounter kbytes_in;
            ByteCounter kbytes_out;
        } all , http, ftp, other;
    } server;

    struct {
        int pkts_sent;
        int queries_sent;
        int replies_sent;
        int pkts_recv;
        int queries_recv;
        int replies_recv;
        int hits_sent;
        int hits_recv;
        int replies_queued;
        int replies_dropped;
        ByteCounter kbytes_sent;
        ByteCounter q_kbytes_sent;
        ByteCounter r_kbytes_sent;
        ByteCounter kbytes_recv;
        ByteCounter q_kbytes_recv;
        ByteCounter r_kbytes_recv;
        StatHist querySvcTime;
        StatHist replySvcTime;
        int query_timeouts;
        int times_used;
    } icp;

    struct {
        int pkts_sent;
        int pkts_recv;
    } htcp;

    struct {
        int requests;
    } unlink;

    struct {
        StatHist svcTime;
    } dns;

    struct {
        int times_used;
        ByteCounter kbytes_sent;
        ByteCounter kbytes_recv;
        ByteCounter memory;
        int msgs_sent;
        int msgs_recv;
#if USE_CACHE_DIGESTS

        CacheDigestGuessStats guess;
#endif

        StatHist on_xition_count;
    } cd;

    struct {
        int times_used;
    } netdb;
    int page_faults;
    unsigned long int select_loops;
    int select_fds;
    double select_time;
    double cputime;

    struct timeval timestamp;
    StatHist comm_udp_incoming;
    StatHist comm_dns_incoming;
    StatHist comm_tcp_incoming;
    StatHist select_fds_hist;

    struct {
        struct {
            int opens;
            int closes;
            int reads;
            int writes;
            int seeks;
            int unlinks;
        } disk;

        struct {
            int accepts;
            int sockets;
            int connects;
            int binds;
            int closes;
            int reads;
            int writes;
            int recvfroms;
            int sendtos;
        } sock;
        int selects;
    } syscalls;
    int aborted_requests;

    struct {
        int files_cleaned;
        int outs;
        int ins;
    } swap;

private:
};

extern StatCounters statCounter;

#endif /* STATCOUNTERS_H_ */

