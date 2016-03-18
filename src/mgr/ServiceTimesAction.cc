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
#include "mgr/ServiceTimesAction.h"
#include "Store.h"
#include "tools.h"

void GetServiceTimesStats(Mgr::ServiceTimesActionData& stats);
void DumpServiceTimesStats(Mgr::ServiceTimesActionData& stats, StoreEntry* sentry);

Mgr::ServiceTimesActionData::ServiceTimesActionData()
{
    memset(this, 0, sizeof(*this));
}

Mgr::ServiceTimesActionData&
Mgr::ServiceTimesActionData::operator += (const ServiceTimesActionData& stats)
{
    for (int i = 0; i < seriesSize; ++i) {
        http_requests5[i] += stats.http_requests5[i];
        http_requests60[i] += stats.http_requests60[i];

        cache_misses5[i] += stats.cache_misses5[i];
        cache_misses60[i] += stats.cache_misses60[i];

        cache_hits5[i] += stats.cache_hits5[i];
        cache_hits60[i] += stats.cache_hits60[i];

        near_hits5[i] += stats.near_hits5[i];
        near_hits60[i] += stats.near_hits60[i];

        not_modified_replies5[i] += stats.not_modified_replies5[i];
        not_modified_replies60[i] += stats.not_modified_replies60[i];

        dns_lookups5[i] += stats.dns_lookups5[i];
        dns_lookups60[i] += stats.dns_lookups60[i];

        icp_queries5[i] += stats.icp_queries5[i];
        icp_queries60[i] += stats.icp_queries60[i];
    }
    ++count;

    return *this;
}

Mgr::ServiceTimesAction::Pointer
Mgr::ServiceTimesAction::Create(const CommandPointer &cmd)
{
    return new ServiceTimesAction(cmd);
}

Mgr::ServiceTimesAction::ServiceTimesAction(const CommandPointer &aCmd):
    Action(aCmd), data()
{
    debugs(16, 5, HERE);
}

void
Mgr::ServiceTimesAction::add(const Action& action)
{
    debugs(16, 5, HERE);
    data += dynamic_cast<const ServiceTimesAction&>(action).data;
}

void
Mgr::ServiceTimesAction::collect()
{
    debugs(16, 5, HERE);
    GetServiceTimesStats(data);
}

void
Mgr::ServiceTimesAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    DumpServiceTimesStats(data, entry);
}

void
Mgr::ServiceTimesAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(data);
}

void
Mgr::ServiceTimesAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(data);
}

