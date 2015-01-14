/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "globals.h"
#include "HttpReply.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "ipc/UdsOp.h"
#include "mgr/Filler.h"
#include "mgr/InfoAction.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"

void GetInfo(Mgr::InfoActionData& stats);
void DumpInfo(Mgr::InfoActionData& stats, StoreEntry* sentry);
void DumpMallocStatistics(StoreEntry* sentry);

Mgr::InfoActionData::InfoActionData()
{
    memset(this, 0, sizeof(*this));
}

Mgr::InfoActionData&
Mgr::InfoActionData::operator += (const InfoActionData& stats)
{
    if (!timerisset(&squid_start) || timercmp(&squid_start, &stats.squid_start, >))
        squid_start = stats.squid_start;
    if (timercmp(&current_time, &stats.current_time, <))
        current_time = stats.current_time;
    client_http_clients += stats.client_http_clients;
    client_http_requests += stats.client_http_requests;
    icp_pkts_recv += stats.icp_pkts_recv;
    icp_pkts_sent += stats.icp_pkts_sent;
    icp_replies_queued += stats.icp_replies_queued;
#if USE_HTCP
    htcp_pkts_recv += stats.htcp_pkts_recv;
    htcp_pkts_sent += stats.htcp_pkts_sent;
#endif
    request_failure_ratio += stats.request_failure_ratio;
    avg_client_http_requests += stats.avg_client_http_requests;
    avg_icp_messages += stats.avg_icp_messages;
    select_loops += stats.select_loops;
    avg_loop_time += stats.avg_loop_time;
    request_hit_ratio5 += stats.request_hit_ratio5;
    request_hit_ratio60 += stats.request_hit_ratio60;
    byte_hit_ratio5 += stats.byte_hit_ratio5;
    byte_hit_ratio60 += stats.byte_hit_ratio60;
    request_hit_mem_ratio5 += stats.request_hit_mem_ratio5;
    request_hit_mem_ratio60 += stats.request_hit_mem_ratio60;
    request_hit_disk_ratio5 += stats.request_hit_disk_ratio5;
    request_hit_disk_ratio60 += stats.request_hit_disk_ratio60;

    store += stats.store;

    unlink_requests += stats.unlink_requests;
    http_requests5 += stats.http_requests5;
    http_requests60 += stats.http_requests60;
    cache_misses5 += stats.cache_misses5;
    cache_misses60 += stats.cache_misses60;
    cache_hits5 += stats.cache_hits5;
    cache_hits60 += stats.cache_hits60;
    near_hits5 += stats.near_hits5;
    near_hits60 += stats.near_hits60;
    not_modified_replies5 += stats.not_modified_replies5;
    not_modified_replies60 += stats.not_modified_replies60;
    dns_lookups5 += stats.dns_lookups5;
    dns_lookups60 += stats.dns_lookups60;
    icp_queries5 += stats.icp_queries5;
    icp_queries60 += stats.icp_queries60;
    if (stats.up_time > up_time)
        up_time = stats.up_time;
    cpu_time += stats.cpu_time;
    cpu_usage += stats.cpu_usage;
    cpu_usage5 += stats.cpu_usage5;
    cpu_usage60 += stats.cpu_usage60;
    maxrss += stats.maxrss;
    page_faults += stats.page_faults;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    ms_bytes_total += stats.ms_bytes_total;
    ms_bytes_free += stats.ms_bytes_free;
#endif
    total_accounted += stats.total_accounted;
    gb_saved_count += stats.gb_saved_count;
    gb_freed_count += stats.gb_freed_count;
    max_fd += stats.max_fd;
    biggest_fd = max(biggest_fd, stats.biggest_fd);
    number_fd += stats.number_fd;
    opening_fd += stats.opening_fd;
    num_fd_free += stats.num_fd_free;
    reserved_fd += stats.reserved_fd;
    ++count;

    return *this;
}

Mgr::InfoAction::Pointer
Mgr::InfoAction::Create(const CommandPointer &cmd)
{
    return new InfoAction(cmd);
}

Mgr::InfoAction::InfoAction(const CommandPointer &aCmd):
    Action(aCmd), data()
{
    debugs(16, 5, HERE);
}

void
Mgr::InfoAction::add(const Action& action)
{
    debugs(16, 5, HERE);
    data += dynamic_cast<const InfoAction&>(action).data;
}

void
Mgr::InfoAction::respond(const Request& request)
{
    debugs(16, 5, HERE);
    Ipc::ImportFdIntoComm(request.conn, SOCK_STREAM, IPPROTO_TCP, Ipc::fdnHttpSocket);
    Must(Comm::IsConnOpen(request.conn));
    Must(request.requestId != 0);
    AsyncJob::Start(new Mgr::Filler(this, request.conn, request.requestId));
}

void
Mgr::InfoAction::collect()
{
    GetInfo(data);
}

void
Mgr::InfoAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);

#if XMALLOC_STATISTICS
    if (UsingSmp())
        storeAppendPrintf(entry, "by kid%d {\n", KidIdentifier);
    DumpMallocStatistics(entry);
    if (UsingSmp())
        storeAppendPrintf(entry, "} by kid%d\n\n", KidIdentifier);
#endif
    if (IamPrimaryProcess())
        DumpInfo(data, entry);
}

void
Mgr::InfoAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(data);
}

void
Mgr::InfoAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(data);
}

