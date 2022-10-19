/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Alex Rousskov, Andres Kroonmaa, Robert Collins
 */

#include "squid.h"
#include "mem/Pool.h"
#include "mem/PoolChunked.h"
#include "mem/PoolMalloc.h"
#include "mem/PoolsManager.h"

#include <cassert>
#include <cstring>

extern time_t squid_curtime;

Mem::PoolMeter TheMeter;
int Pool_id_counter = 0;

/* Persistent Pool stats. for GlobalStats accumulation */
static MemPoolStats pp_stats;

/*
 * Totals statistics is returned
 */
int
memPoolGetGlobalStats(MemPoolGlobalStats * stats)
{
    memset(stats, 0, sizeof(MemPoolGlobalStats));
    memset(&pp_stats, 0, sizeof(MemPoolStats));

    Mem::PoolsManager::GetInstance().flushMeters(); /* recreate TheMeter */

    /* gather all stats for Totals */
    int pools_inuse = 0;
    for (auto *pool : Mem::PoolsManager::GetInstance().pools) {
        if (pool->getStats(&pp_stats) > 0)
            ++pools_inuse;
    }

    stats->TheMeter = &TheMeter;

    stats->tot_pools_alloc = Mem::PoolsManager::GetInstance().pools.size();
    stats->tot_pools_inuse = pools_inuse;
    stats->tot_pools_mempid = Pool_id_counter;

    stats->tot_chunks_alloc = pp_stats.chunks_alloc;
    stats->tot_chunks_inuse = pp_stats.chunks_inuse;
    stats->tot_chunks_partial = pp_stats.chunks_partial;
    stats->tot_chunks_free = pp_stats.chunks_free;
    stats->tot_items_alloc = pp_stats.items_alloc;
    stats->tot_items_inuse = pp_stats.items_inuse;
    stats->tot_items_idle = pp_stats.items_idle;

    stats->tot_overhead += pp_stats.overhead + Mem::PoolsManager::GetInstance().pools.size() * sizeof(Mem::AllocatorBase *);
    stats->mem_idle_limit = Mem::PoolsManager::GetInstance().mem_idle_limit;

    return pools_inuse;
}

int
memPoolsTotalAllocated(void)
{
    MemPoolGlobalStats stats;
    memPoolGetGlobalStats(&stats);
    return stats.TheMeter->alloc.currentLevel();
}
