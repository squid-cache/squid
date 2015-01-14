/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_MGR_INTERVAL_ACTION_H
#define SQUID_MGR_INTERVAL_ACTION_H

#include "mgr/Action.h"

namespace Mgr
{

/// auxiliary class which store stats computed
/// from StatCounters for specified interval
class IntervalActionData
{
public:
    IntervalActionData();
    IntervalActionData& operator += (const IntervalActionData& stats);

public:
    struct timeval sample_start_time;
    struct timeval sample_end_time;
    double client_http_requests;
    double client_http_hits;
    double client_http_errors;
    double client_http_kbytes_in;
    double client_http_kbytes_out;
    double client_http_all_median_svc_time;
    double client_http_miss_median_svc_time;
    double client_http_nm_median_svc_time;
    double client_http_nh_median_svc_time;
    double client_http_hit_median_svc_time;
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
    double icp_query_median_svc_time;
    double icp_reply_median_svc_time;
    double dns_median_svc_time;
    double unlink_requests;
    double page_faults;
    double select_loops;
    double select_fds;
    double average_select_fd_period;
    double median_select_fds;
    double swap_outs;
    double swap_ins;
    double swap_files_cleaned;
    double aborted_requests;
    double syscalls_disk_opens;
    double syscalls_disk_closes;
    double syscalls_disk_reads;
    double syscalls_disk_writes;
    double syscalls_disk_seeks;
    double syscalls_disk_unlinks;
    double syscalls_sock_accepts;
    double syscalls_sock_sockets;
    double syscalls_sock_connects;
    double syscalls_sock_binds;
    double syscalls_sock_closes;
    double syscalls_sock_reads;
    double syscalls_sock_writes;
    double syscalls_sock_recvfroms;
    double syscalls_sock_sendtos;
    double syscalls_selects;
    double cpu_time;
    double wall_time;
    unsigned int count;
};

/// implement aggregated interval actions
class IntervalAction: public Action
{
protected:
    IntervalAction(const CommandPointer &cmd, int aMinutes, int aHours);

public:
    static Pointer Create5min(const CommandPointer &cmd);
    static Pointer Create60min(const CommandPointer &cmd);
    /* Action API */
    virtual void add(const Action& action);
    virtual void pack(Ipc::TypedMsgHdr& msg) const;
    virtual void unpack(const Ipc::TypedMsgHdr& msg);

protected:
    /* Action API */
    virtual void collect();
    virtual void dump(StoreEntry* entry);

private:
    int minutes;
    int hours;
    IntervalActionData data;
};

} // namespace Mgr

#endif /* SQUID_MGR_INTERVAL_ACTION_H */

