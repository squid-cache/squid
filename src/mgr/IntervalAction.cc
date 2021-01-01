/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
#include "mgr/IntervalAction.h"
#include "SquidMath.h"
#include "Store.h"
#include "tools.h"

void GetAvgStat(Mgr::IntervalActionData& stats, int minutes, int hours);
void DumpAvgStat(Mgr::IntervalActionData& stats, StoreEntry* sentry);

Mgr::IntervalActionData::IntervalActionData()
{
    memset(this, 0, sizeof(*this));
}

Mgr::IntervalActionData&
Mgr::IntervalActionData::operator += (const IntervalActionData& stats)
{
    if (!timerisset(&sample_start_time) || timercmp(&sample_start_time, &stats.sample_start_time, >))
        sample_start_time = stats.sample_start_time;
    if (timercmp(&sample_end_time, &stats.sample_end_time, <))
        sample_end_time = stats.sample_end_time;
    client_http_requests += stats.client_http_requests;
    client_http_hits += stats.client_http_hits;
    client_http_errors += stats.client_http_errors;
    client_http_kbytes_in += stats.client_http_kbytes_in;
    client_http_kbytes_out += stats.client_http_kbytes_out;
    client_http_all_median_svc_time += stats.client_http_all_median_svc_time;
    client_http_miss_median_svc_time += stats.client_http_miss_median_svc_time;
    client_http_nm_median_svc_time += stats.client_http_nm_median_svc_time;
    client_http_nh_median_svc_time += stats.client_http_nh_median_svc_time;
    client_http_hit_median_svc_time += stats.client_http_hit_median_svc_time;
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
    icp_query_median_svc_time += stats.icp_query_median_svc_time;
    icp_reply_median_svc_time += stats.icp_reply_median_svc_time;
    dns_median_svc_time += stats.dns_median_svc_time;
    unlink_requests += stats.unlink_requests;
    page_faults += stats.page_faults;
    select_loops += stats.select_loops;
    select_fds += stats.select_fds;
    average_select_fd_period += stats.average_select_fd_period;
    median_select_fds += stats.median_select_fds;
    swap_outs += stats.swap_outs;
    swap_ins += stats.swap_ins;
    swap_files_cleaned += stats.swap_files_cleaned;
    aborted_requests += stats.aborted_requests;
    syscalls_disk_opens += stats.syscalls_disk_opens;
    syscalls_disk_closes += stats.syscalls_disk_closes;
    syscalls_disk_reads += stats.syscalls_disk_reads;
    syscalls_disk_writes += stats.syscalls_disk_writes;
    syscalls_disk_seeks += stats.syscalls_disk_seeks;
    syscalls_disk_unlinks += stats.syscalls_disk_unlinks;
    syscalls_sock_accepts += stats.syscalls_sock_accepts;
    syscalls_sock_sockets += stats.syscalls_sock_sockets;
    syscalls_sock_connects += stats.syscalls_sock_connects;
    syscalls_sock_binds += stats.syscalls_sock_binds;
    syscalls_sock_closes += stats.syscalls_sock_closes;
    syscalls_sock_reads += stats.syscalls_sock_reads;
    syscalls_sock_writes += stats.syscalls_sock_writes;
    syscalls_sock_recvfroms += stats.syscalls_sock_recvfroms;
    syscalls_sock_sendtos += stats.syscalls_sock_sendtos;
    syscalls_selects += stats.syscalls_selects;
    cpu_time += stats.cpu_time;
    wall_time += stats.wall_time;
    ++count;

    return *this;
}

Mgr::IntervalAction::Pointer
Mgr::IntervalAction::Create5min(const CommandPointer &cmd)
{
    return new IntervalAction(cmd, 5, 0);
}

Mgr::IntervalAction::Pointer
Mgr::IntervalAction::Create60min(const CommandPointer &cmd)
{
    return new IntervalAction(cmd, 60, 0);
}

Mgr::IntervalAction::IntervalAction(const CommandPointer &aCmd, int aMinutes, int aHours):
    Action(aCmd), minutes(aMinutes), hours(aHours), data()
{
    debugs(16, 5, HERE);
}

void
Mgr::IntervalAction::add(const Action& action)
{
    debugs(16, 5, HERE);
    data += dynamic_cast<const IntervalAction&>(action).data;
}

void
Mgr::IntervalAction::collect()
{
    GetAvgStat(data, minutes, hours);
}

void
Mgr::IntervalAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    DumpAvgStat(data, entry);
}

void
Mgr::IntervalAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(data);
}

void
Mgr::IntervalAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(data);
}

