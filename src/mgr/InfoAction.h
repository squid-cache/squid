/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_INFO_ACTION_H
#define SQUID_MGR_INFO_ACTION_H

#include "mgr/Action.h"
#include "StoreStats.h"

namespace Mgr
{

/// store general runtime information
/// and memory usage
class InfoActionData
{
public:
    InfoActionData();
    InfoActionData& operator += (const InfoActionData& stats);

public:
    struct timeval squid_start;
    struct timeval current_time;
    double client_http_clients;
    double client_http_requests;
    double icp_pkts_recv;
    double icp_pkts_sent;
    double icp_replies_queued;
#if USE_HTCP
    double htcp_pkts_recv;
    double htcp_pkts_sent;
#endif
    double request_failure_ratio;
    double avg_client_http_requests;
    double avg_icp_messages;
    double select_loops;
    double avg_loop_time;
    double request_hit_ratio5;
    double request_hit_ratio60;
    double byte_hit_ratio5;
    double byte_hit_ratio60;
    double request_hit_mem_ratio5;
    double request_hit_mem_ratio60;
    double request_hit_disk_ratio5;
    double request_hit_disk_ratio60;

    StoreInfoStats store; ///< disk and memory cache statistics

    double unlink_requests;
    double http_requests5;
    double http_requests60;
    double cache_misses5;
    double cache_misses60;
    double cache_hits5;
    double cache_hits60;
    double near_hits5;
    double near_hits60;
    double not_modified_replies5;
    double not_modified_replies60;
    double dns_lookups5;
    double dns_lookups60;
    double icp_queries5;
    double icp_queries60;
    double up_time;
    double cpu_time;
    double cpu_usage;
    double cpu_usage5;
    double cpu_usage60;
    double maxrss;
    double page_faults;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    double ms_bytes_total;
    double ms_bytes_free;
#endif
    double total_accounted;
    double gb_saved_count;
    double gb_freed_count;
    double max_fd;
    double biggest_fd;
    double number_fd;
    double opening_fd;
    double num_fd_free;
    double reserved_fd;
    unsigned int count;
};

/// implement aggregated 'info' action
class InfoAction: public Action
{
protected:
    InfoAction(const CommandPointer &cmd);

public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    virtual void add(const Action& action);
    virtual void respond(const Request& request);
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual void unpack(const Ipc::TypedMsgHdr& msg);

protected:
    /* Action API */
    virtual void collect();
    virtual void dump(StoreEntry* entry);

private:
    InfoActionData data;
};

} // namespace Mgr

#endif /* SQUID_MGR_INFO_ACTION_H */

