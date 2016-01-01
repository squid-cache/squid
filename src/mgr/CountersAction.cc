/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/CountersAction.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"

void GetCountersStats(Mgr::CountersActionData& stats);
void DumpCountersStats(Mgr::CountersActionData& stats, StoreEntry* sentry);

Mgr::CountersActionData::CountersActionData()
{
    memset(this, 0, sizeof(*this));
}

Mgr::CountersActionData&
Mgr::CountersActionData::operator += (const CountersActionData& stats)
{
    if (timercmp(&sample_time, &stats.sample_time, <))
        sample_time = stats.sample_time;
    client_http_requests += stats.client_http_requests;
    client_http_hits += stats.client_http_hits;
    client_http_errors += stats.client_http_errors;
    client_http_kbytes_in += stats.client_http_kbytes_in;
    client_http_kbytes_out += stats.client_http_kbytes_out;
    client_http_hit_kbytes_out += stats.client_http_hit_kbytes_out;
    server_all_requests += stats.server_all_requests;
    server_all_errors += stats.server_all_errors;
    server_all_kbytes_in += stats.server_all_kbytes_in;
    server_all_kbytes_out += stats.server_all_kbytes_out;
    server_http_requests += stats.server_http_requests;
    server_http_errors += stats.server_http_errors;
    server_http_kbytes_in += stats.server_http_kbytes_in;
    server_http_kbytes_out += stats.server_http_kbytes_out;
    server_ftp_requests += stats.server_ftp_requests;
    server_ftp_errors += stats.server_ftp_errors;
    server_ftp_kbytes_in += stats.server_ftp_kbytes_in;
    server_ftp_kbytes_out += stats.server_ftp_kbytes_out;
    server_other_requests += stats.server_other_requests;
    server_other_errors += stats.server_other_errors;
    server_other_kbytes_in += stats.server_other_kbytes_in;
    server_other_kbytes_out += stats.server_other_kbytes_out;
    icp_pkts_sent += stats.icp_pkts_sent;
    icp_pkts_recv += stats.icp_pkts_recv;
    icp_queries_sent += stats.icp_queries_sent;
    icp_replies_sent += stats.icp_replies_sent;
    icp_queries_recv += stats.icp_queries_recv;
    icp_replies_recv += stats.icp_replies_recv;
    icp_replies_queued += stats.icp_replies_queued;
    icp_query_timeouts += stats.icp_query_timeouts;
    icp_kbytes_sent += stats.icp_kbytes_sent;
    icp_kbytes_recv += stats.icp_kbytes_recv;
    icp_q_kbytes_sent += stats.icp_q_kbytes_sent;
    icp_r_kbytes_sent += stats.icp_r_kbytes_sent;
    icp_q_kbytes_recv += stats.icp_q_kbytes_recv;
    icp_r_kbytes_recv += stats.icp_r_kbytes_recv;
#if USE_CACHE_DIGESTS
    icp_times_used += stats.icp_times_used;
    cd_times_used += stats.cd_times_used;
    cd_msgs_sent += stats.cd_msgs_sent;
    cd_msgs_recv += stats.cd_msgs_recv;
    cd_memory += stats.cd_memory;
    cd_local_memory += stats.cd_local_memory;
    cd_kbytes_sent += stats.cd_kbytes_sent;
    cd_kbytes_recv += stats.cd_kbytes_recv;
#endif
    unlink_requests += stats.unlink_requests;
    page_faults += stats.page_faults;
    select_loops += stats.select_loops;
    cpu_time += stats.cpu_time;
    wall_time += stats.wall_time;
    swap_outs += stats.swap_outs;
    swap_ins += stats.swap_ins;
    swap_files_cleaned += stats.swap_files_cleaned;
    aborted_requests += stats.aborted_requests;

    return *this;
}

Mgr::CountersAction::Pointer
Mgr::CountersAction::Create(const CommandPointer &cmd)
{
    return new CountersAction(cmd);
}

Mgr::CountersAction::CountersAction(const CommandPointer &aCmd):
    Action(aCmd), data()
{
    debugs(16, 5, HERE);
}

void
Mgr::CountersAction::add(const Action& action)
{
    debugs(16, 5, HERE);
    data += dynamic_cast<const CountersAction&>(action).data;
}

void
Mgr::CountersAction::collect()
{
    debugs(16, 5, HERE);
    GetCountersStats(data);
}

void
Mgr::CountersAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    DumpCountersStats(data, entry);
}

void
Mgr::CountersAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(data);
}

void
Mgr::CountersAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(data);
}

