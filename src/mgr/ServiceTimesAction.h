/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_SERVICETIMESACTION_H
#define SQUID_SRC_MGR_SERVICETIMESACTION_H

#include "mgr/Action.h"

namespace Mgr
{

/// store service times for 5 and 60 min
class ServiceTimesActionData
{
public:
    enum { seriesSize = 19 };

public:
    ServiceTimesActionData();
    ServiceTimesActionData& operator += (const ServiceTimesActionData& stats);

public:
    double http_requests5[seriesSize];
    double http_requests60[seriesSize];
    double cache_misses5[seriesSize];
    double cache_misses60[seriesSize];
    double cache_hits5[seriesSize];
    double cache_hits60[seriesSize];
    double near_hits5[seriesSize];
    double near_hits60[seriesSize];
    double not_modified_replies5[seriesSize];
    double not_modified_replies60[seriesSize];
    double dns_lookups5[seriesSize];
    double dns_lookups60[seriesSize];
    double icp_queries5[seriesSize];
    double icp_queries60[seriesSize];
    unsigned int count;
};

/// implement aggregated 'service_times' action
class ServiceTimesAction: public Action
{
protected:
    ServiceTimesAction(const CommandPointer &cmd);

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
    ServiceTimesActionData data;
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_SERVICETIMESACTION_H */

