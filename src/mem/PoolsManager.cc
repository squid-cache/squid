/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/Pool.h"
#include "mem/PoolChunked.h"
#include "mem/PoolMalloc.h"
#include "mem/PoolsManager.h"

Mem::PoolsManager::PoolsManager()
{
    if (char *cfg = getenv("MEMPOOLS"))
        defaultIsChunked = atoi(cfg);
}

Mem::PoolsManager &
Mem::PoolsManager::GetInstance()
{
    // We must initialize on first use (which may happen during static
    // initialization) and preserve until the last user is gone (which
    // may happen long after main() exit). We currently preserve forever.
    static auto *Instance = new Mem::PoolsManager;
    return *Instance;
}

Mem::AllocatorMetrics *
Mem::PoolsManager::create(const char *label, size_t objectSize)
{
    if (defaultIsChunked)
        return new MemPoolChunked(label, objectSize);
    else
        return new MemPoolMalloc(label, objectSize);
}

/*
 * Returns all cached frees to their home chunks
 * If chunks unreferenced age is over, destroys Idle chunk
 * Flushes meters for a pool
 * When used for all pools, if new_idle_limit is above -1, new
 * idle memory limit is set before Cleanup. This allows to shrink
 * pool memory usage to specified minimum.
 */
void
Mem::PoolsManager::clean(time_t maxage)
{
    flushMeters();
    if (mem_idle_limit < 0) // no limit to enforce
        return;

    int shift = 1;
    if (TheMeter.idle.currentLevel() > mem_idle_limit)
        maxage = shift = 0;

    for (auto *pool : pools) {
        if (pool->idleTrigger(shift))
            pool->clean(maxage);
    }
}

/// update all pool counters, and recreates TheMeter totals from all pools
void
Mem::PoolsManager::flushMeters()
{
    TheMeter.flush();

    for (auto *pool : pools) {
        pool->flushMetersFull();
        // are these TheMeter grow() operations or accumulated volumes ?
        TheMeter.alloc += pool->getMeter().alloc.currentLevel() * pool->obj_size;
        TheMeter.inuse += pool->getMeter().inuse.currentLevel() * pool->obj_size;
        TheMeter.idle += pool->getMeter().idle.currentLevel() * pool->obj_size;

        TheMeter.gb_allocated.count += pool->getMeter().gb_allocated.count;
        TheMeter.gb_saved.count += pool->getMeter().gb_saved.count;
        TheMeter.gb_freed.count += pool->getMeter().gb_freed.count;
        TheMeter.gb_allocated.bytes += pool->getMeter().gb_allocated.bytes;
        TheMeter.gb_saved.bytes += pool->getMeter().gb_saved.bytes;
        TheMeter.gb_freed.bytes += pool->getMeter().gb_freed.bytes;
    }
}
