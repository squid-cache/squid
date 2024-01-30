/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_INFOACTION_H
#define SQUID_SRC_MGR_INFOACTION_H

#include "mgr/Action.h"
#include "StoreStats.h"

namespace Mgr
{

/// store general runtime information
/// and memory usage
class InfoActionData
{
public:
    InfoActionData& operator += (const InfoActionData& stats);

public:
    struct timeval squid_start = {};
    struct timeval current_time = {};
    double client_http_clients = 0.0;
    double client_http_requests = 0.0;
    double icp_pkts_recv = 0.0;
    double icp_pkts_sent = 0.0;
    double icp_replies_queued = 0.0;
#if USE_HTCP
    double htcp_pkts_recv = 0.0;
    double htcp_pkts_sent = 0.0;
#endif
    double request_failure_ratio = 0.0;
    double avg_client_http_requests = 0.0;
    double avg_icp_messages = 0.0;
    double select_loops = 0.0;
    double avg_loop_time = 0.0;
    double request_hit_ratio5 = 0.0;
    double request_hit_ratio60 = 0.0;
    double byte_hit_ratio5 = 0.0;
    double byte_hit_ratio60 = 0.0;
    double request_hit_mem_ratio5 = 0.0;
    double request_hit_mem_ratio60 = 0.0;
    double request_hit_disk_ratio5 = 0.0;
    double request_hit_disk_ratio60 = 0.0;

    StoreInfoStats store; ///< disk and memory cache statistics

    double unlink_requests = 0.0;
    double http_requests5 = 0.0;
    double http_requests60 = 0.0;
    double cache_misses5 = 0.0;
    double cache_misses60 = 0.0;
    double cache_hits5 = 0.0;
    double cache_hits60 = 0.0;
    double near_hits5 = 0.0;
    double near_hits60 = 0.0;
    double not_modified_replies5 = 0.0;
    double not_modified_replies60 = 0.0;
    double dns_lookups5 = 0.0;
    double dns_lookups60 = 0.0;
    double icp_queries5 = 0.0;
    double icp_queries60 = 0.0;
    double up_time = 0.0;
    double cpu_time = 0.0;
    double cpu_usage = 0.0;
    double cpu_usage5 = 0.0;
    double cpu_usage60 = 0.0;
    double maxrss = 0.0;
    double page_faults = 0.0;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    double ms_bytes_total = 0.0;
    double ms_bytes_free = 0.0;
#endif
    double total_accounted = 0.0;
    double gb_saved_count = 0.0;
    double gb_freed_count = 0.0;
    double max_fd = 0.0;
    double biggest_fd = 0.0;
    double number_fd = 0.0;
    double opening_fd = 0.0;
    double num_fd_free = 0.0;
    double reserved_fd = 0.0;
    unsigned int count = 0;
};

/// implement aggregated 'info' action
class InfoAction: public Action
{
protected:
    InfoAction(const CommandPointer &cmd);

public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void add(const Action& action) override;
    void respond(const Request& request) override;
    void pack(Ipc::TypedMsgHdr& msg) const override;
    void unpack(const Ipc::TypedMsgHdr& msg) override;

protected:
    /* Action API */
    void collect() override;
    void dump(StoreEntry* entry) override;

private:
    InfoActionData data;
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_INFOACTION_H */

