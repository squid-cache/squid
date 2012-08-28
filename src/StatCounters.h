/*
 * AUTHOR: Francesco Chemolli (Harvest-derived)
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
 *
 */
#ifndef STATCOUNTERS_H_
#define STATCOUNTERS_H_

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
        kb_t kbytes_in;
        kb_t kbytes_out;
        kb_t hit_kbytes_out;
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
            kb_t kbytes_in;
            kb_t kbytes_out;
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
        kb_t kbytes_sent;
        kb_t q_kbytes_sent;
        kb_t r_kbytes_sent;
        kb_t kbytes_recv;
        kb_t q_kbytes_recv;
        kb_t r_kbytes_recv;
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
        kb_t kbytes_sent;
        kb_t kbytes_recv;
        kb_t memory;
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
