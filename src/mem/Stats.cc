/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/Allocator.h"
#include "mem/Pool.h"
#include "mem/Stats.h"

size_t
Mem::GlobalStats(PoolStats &stats)
{
    MemPools::GetInstance().flushMeters();

    stats.meter = &TheMeter;
    stats.label = "Total";
    stats.obj_size = 1;
    stats.overhead += sizeof(MemPools);

    /* gather all stats for Totals */
    size_t pools_inuse = 0;
    for (const auto pool: MemPools::GetInstance().pools) {
        if (pool->getStats(stats) > 0)
            ++pools_inuse;
        stats.overhead += sizeof(Allocator *);
    }

    return pools_inuse;
}
