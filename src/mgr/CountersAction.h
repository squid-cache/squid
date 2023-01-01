/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_COUNTERS_ACTION_H
#define SQUID_MGR_COUNTERS_ACTION_H

#include "mgr/Action.h"

namespace Mgr
{

/// store traffic and resource counters
class CountersActionData
{
public:
    CountersActionData();
    CountersActionData& operator += (const CountersActionData& stats);

public:
    struct timeval sample_time;
    double client_http_requests;
    double client_http_hits;
    double client_http_errors;
    double client_http_kbytes_in;
    double client_http_kbytes_out;
    double client_http_hit_kbytes_out;
    double server_all_requests;
    double server_all_errors;
    double server_all_kbytes_in;
    double server_all_kbytes_out;
    double server_http_requests;
    double server_http_errors;
    double server_http_kbytes_in;
    double server_http_kbytes_out;
    double server_ftp_requests;
    double server_ftp_errors;
    double server_ftp_kbytes_in;
    double server_ftp_kbytes_out;
    double server_other_requests;
    double server_other_errors;
    double server_other_kbytes_in;
    double server_other_kbytes_out;
    double icp_pkts_sent;
    double icp_pkts_recv;
    double icp_queries_sent;
    double icp_replies_sent;
    double icp_queries_recv;
    double icp_replies_recv;
    double icp_replies_queued;
    double icp_query_timeouts;
    double icp_kbytes_sent;
    double icp_kbytes_recv;
    double icp_q_kbytes_sent;
    double icp_r_kbytes_sent;
    double icp_q_kbytes_recv;
    double icp_r_kbytes_recv;
#if USE_CACHE_DIGESTS
    double icp_times_used;
    double cd_times_used;
    double cd_msgs_sent;
    double cd_msgs_recv;
    double cd_memory;
    double cd_local_memory;
    double cd_kbytes_sent;
    double cd_kbytes_recv;
#endif
    double unlink_requests;
    double page_faults;
    double select_loops;
    double cpu_time;
    double wall_time;
    double swap_outs;
    double swap_ins;
    double swap_files_cleaned;
    double aborted_requests;
    double hitValidationAttempts;
    double hitValidationRefusalsDueToLocking;
    double hitValidationRefusalsDueToZeroSize;
    double hitValidationRefusalsDueToTimeLimit;
    double hitValidationFailures;
};

/// implement aggregated 'counters' action
class CountersAction: public Action
{
protected:
    CountersAction(const CommandPointer &cmd);

public:
    static Pointer Create(const CommandPointer &cmd);
    /* Action API */
    void add(const Action& action) override;
    void pack(Ipc::TypedMsgHdr& msg) const override;
    void unpack(const Ipc::TypedMsgHdr& msg) override;

protected:
    /* Action API */
    void collect() override;
    void dump(StoreEntry* entry) override;

private:
    CountersActionData data;
};

} // namespace Mgr

#endif /* SQUID_MGR_COUNTERS_ACTION_H */

