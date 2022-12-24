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
#include "mem/PoolChunked.h"
#include "mem/PoolMalloc.h"
#include "mem/Stats.h"

#include <cassert>
#include <cstring>

#define FLUSH_LIMIT 1000    /* Flush memPool counters to memMeters after flush limit calls */

extern time_t squid_curtime;

Mem::PoolMeter TheMeter;

MemPools &
MemPools::GetInstance()
{
    // We must initialize on first use (which may happen during static
    // initialization) and preserve until the last user is gone (which
    // may happen long after main() exit). We currently preserve forever.
    static MemPools *Instance = new MemPools;
    return *Instance;
}

/* Change the default value of defaultIsChunked to override
 * all pools - including those used before main() starts where
 * MemPools::GetInstance().setDefaultPoolChunking() can be called.
 */
MemPools::MemPools()
{
    if (char *cfg = getenv("MEMPOOLS"))
        defaultIsChunked = atoi(cfg);
}

MemImplementingAllocator *
MemPools::create(const char *label, size_t obj_size)
{
    // TODO Use ref-counted Pointer for pool lifecycle management
    // that is complicated by all the global static pool pointers.
    // For now leak these Allocator descendants on shutdown.

    MemImplementingAllocator *newPool;
    if (defaultIsChunked)
        newPool = new MemPoolChunked(label, obj_size);
    else
        newPool = new MemPoolMalloc(label, obj_size);
    pools.push_back(newPool);
    return pools.back();
}

void
MemPools::setDefaultPoolChunking(bool const &aBool)
{
    defaultIsChunked = aBool;
}

void
MemImplementingAllocator::flushMeters()
{
    size_t calls;

    calls = free_calls;
    if (calls) {
        meter.gb_freed.count += calls;
        free_calls = 0;
    }
    calls = alloc_calls;
    if (calls) {
        meter.gb_allocated.count += calls;
        alloc_calls = 0;
    }
    calls = saved_calls;
    if (calls) {
        meter.gb_saved.count += calls;
        saved_calls = 0;
    }
}

void
MemImplementingAllocator::flushMetersFull()
{
    flushMeters();
    getMeter().gb_allocated.bytes = getMeter().gb_allocated.count * obj_size;
    getMeter().gb_saved.bytes = getMeter().gb_saved.count * obj_size;
    getMeter().gb_freed.bytes = getMeter().gb_freed.count * obj_size;
}

/*
 * Updates all pool counters, and recreates TheMeter totals from all pools
 */
void
MemPools::flushMeters()
{
    TheMeter.flush();

    for (const auto pool: pools) {
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

void *
MemImplementingAllocator::alloc()
{
    if (++alloc_calls == FLUSH_LIMIT)
        flushMeters();

    return allocate();
}

void
MemImplementingAllocator::freeOne(void *obj)
{
    assert(obj != nullptr);
    (void) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(obj, obj_size);
    deallocate(obj, MemPools::GetInstance().idleLimit() == 0);
    ++free_calls;
}

/*
 * Returns all cached frees to their home chunks
 * If chunks unreferenced age is over, destroys Idle chunk
 * Flushes meters for a pool
 * If pool is not specified, iterates through all pools.
 * When used for all pools, if new_idle_limit is above -1, new
 * idle memory limit is set before Cleanup. This allows to shrink
 * memPool memory usage to specified minimum.
 */
void
MemPools::clean(time_t maxage)
{
    flushMeters();
    if (idleLimit() < 0) // no limit to enforce
        return;

    int shift = 1;
    if (TheMeter.idle.currentLevel() > idleLimit())
        maxage = shift = 0;

    for (const auto pool: pools) {
        if (pool->idleTrigger(shift))
            pool->clean(maxage);
    }
}

MemImplementingAllocator::MemImplementingAllocator(char const * const aLabel, const size_t aSize):
    Mem::Allocator(aLabel),
    alloc_calls(0),
    free_calls(0),
    saved_calls(0),
    obj_size(RoundedSize(aSize))
{
    assert(aLabel != nullptr && aSize);
}

Mem::PoolMeter const &
MemImplementingAllocator::getMeter() const
{
    return meter;
}

Mem::PoolMeter &
MemImplementingAllocator::getMeter()
{
    return meter;
}

size_t
MemImplementingAllocator::objectSize() const
{
    return obj_size;
}

