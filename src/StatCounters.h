/*
 * StatCounters.h
 *
 *  Created on: Dec 9, 2011
 *      Author: kinkie
 */

#ifndef STATCOUNTERS_H_
#define STATCOUNTERS_H_

#include "config.h"

#include "StatHist.h"

#if USE_CACHE_DIGESTS
/* statistics for cache digests and other hit "predictors" */
class cd_guess_stats {
public:
    /* public, read-only */
    int true_hits;
    int false_hits;
    int true_misses;
    int false_misses;
    int close_hits;     /* tmp, remove it later */
};
#endif


/*
 * if you add a field to StatCounters,
 * you MUST sync statCountersInitSpecial, statCountersClean, and statCountersCopy
 */
class StatCounters {
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
        StatHist miss_svc_time;
        StatHist nm_svc_time;
        StatHist nh_svc_time;
        StatHist hit_svc_time;
        StatHist all_svc_time;
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
        StatHist query_svc_time;
        StatHist reply_svc_time;
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
        StatHist svc_time;
    } dns;

    struct {
        int times_used;
        kb_t kbytes_sent;
        kb_t kbytes_recv;
        kb_t memory;
        int msgs_sent;
        int msgs_recv;
#if USE_CACHE_DIGESTS

        cd_guess_stats guess;
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
    StatHist comm_icp_incoming;
    StatHist comm_dns_incoming;
    StatHist comm_http_incoming;
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
};


#endif /* STATCOUNTERS_H_ */
