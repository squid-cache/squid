/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/AllocatorMetrics.h"
#include "mem/PoolsManager.h"

/// Flush memPool counters to memMeters after flush limit calls
#define FLUSH_LIMIT 1000

void
Mem::PoolMeter::flush()
{
    alloc.flush();
    inuse.flush();
    idle.flush();
    gb_allocated.count = 0;
    gb_allocated.bytes = 0;
    gb_oallocated.count = 0;
    gb_oallocated.bytes = 0;
    gb_saved.count = 0;
    gb_saved.bytes = 0;
    gb_freed.count = 0;
    gb_freed.bytes = 0;
}

Mem::AllocatorMetrics::AllocatorMetrics(char const *aLabel, size_t aSize) :
    Mem::AllocatorBase(aLabel),
    obj_size(RoundedSize(aSize))
{
    assert(aLabel);
    assert(aSize);

    memPID = ++Pool_id_counter;

    PoolsManager::GetInstance().registerPool(this);
}

Mem::AllocatorMetrics::~AllocatorMetrics()
{
    PoolsManager::GetInstance().unregisterPool(this);
}

void
Mem::AllocatorMetrics::flushMetersFull()
{
    flushMeters();
    getMeter().gb_allocated.bytes = getMeter().gb_allocated.count * obj_size;
    getMeter().gb_saved.bytes = getMeter().gb_saved.count * obj_size;
    getMeter().gb_freed.bytes = getMeter().gb_freed.count * obj_size;
}

void
Mem::AllocatorMetrics::flushMeters()
{
    // XXX: looks like a broken attempt at TOCTOU avoidance. drop 'calls' local.
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

void *
Mem::AllocatorMetrics::alloc()
{
    if (++alloc_calls == FLUSH_LIMIT)
        flushMeters();

    return allocate();
}

void
Mem::AllocatorMetrics::freeOne(void *obj)
{
    assert(obj != nullptr);
    (void) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(obj, obj_size);
    deallocate(obj, PoolsManager::GetInstance().mem_idle_limit == 0);
    ++free_calls;
}
