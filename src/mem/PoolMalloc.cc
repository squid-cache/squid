/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Alex Rousskov, Andres Kroonmaa, Robert Collins, Henrik Nordstrom
 */

#include "squid.h"
#include "mem/Pool.h"
#include "mem/PoolMalloc.h"
#include "mem/Stats.h"

#include <cassert>
#include <cstring>

extern time_t squid_curtime;

void *
MemPoolMalloc::allocate()
{
    void *obj = nullptr;
    if (!freelist.empty()) {
        obj = freelist.top();
        freelist.pop();
    }
    if (obj) {
        --meter.idle;
        ++countSavedAllocs;
    } else {
        if (doZero)
            obj = xcalloc(1, objectSize);
        else
            obj = xmalloc(objectSize);
        ++meter.alloc;
    }
    ++meter.inuse;
    return obj;
}

void
MemPoolMalloc::deallocate(void *obj)
{
    --meter.inuse;
    if (MemPools::GetInstance().idleLimit() == 0) {
        xfree(obj);
        --meter.alloc;
    } else {
        if (doZero)
            memset(obj, 0, objectSize);
        ++meter.idle;
        freelist.push(obj);
    }
}

/* TODO extract common logic to MemAllocate */
size_t
MemPoolMalloc::getStats(Mem::PoolStats &stats)
{
    stats.pool = this;
    stats.label = label;
    stats.meter = &meter;
    stats.obj_size = objectSize;
    stats.chunk_capacity = 0;

    stats.items_alloc += meter.alloc.currentLevel();
    stats.items_inuse += meter.inuse.currentLevel();
    stats.items_idle += meter.idle.currentLevel();

    stats.overhead += sizeof(*this) + strlen(label) + 1;

    return getInUseCount();
}

MemPoolMalloc::MemPoolMalloc(char const *aLabel, size_t aSize) :
    Mem::Allocator(aLabel, aSize)
{
}

MemPoolMalloc::~MemPoolMalloc()
{
    assert(getInUseCount() == 0);
    clean(0);
}

bool
MemPoolMalloc::idleTrigger(int shift) const
{
    return freelist.size() >> (shift ? 8 : 0);
}

void
MemPoolMalloc::clean(time_t)
{
    while (!freelist.empty()) {
        void *obj = freelist.top();
        freelist.pop();
        --meter.idle;
        --meter.alloc;
        xfree(obj);
    }
}

