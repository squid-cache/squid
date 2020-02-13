/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 63    Low Level Memory Pool Management
 * AUTHOR: Alex Rousskov, Andres Kroonmaa, Robert Collins, Henrik Nordstrom
 */

#include "squid.h"
#include "mem/PoolMalloc.h"

#include <cassert>
#include <cstring>

extern time_t squid_curtime;

void *
MemPoolMalloc::allocate()
{
    void *obj = NULL;
    if (!freelist.empty()) {
        obj = freelist.top();
        freelist.pop();
    }
    if (obj) {
        --meter.idle;
        ++saved_calls;
    } else {
        if (doZero)
            obj = xcalloc(1, obj_size);
        else
            obj = xmalloc(obj_size);
        ++meter.alloc;
    }
    ++meter.inuse;
    return obj;
}

void
MemPoolMalloc::deallocate(void *obj, bool aggressive)
{
    --meter.inuse;
    if (aggressive) {
        xfree(obj);
        --meter.alloc;
    } else {
        if (doZero)
            memset(obj, 0, obj_size);
        ++meter.idle;
        freelist.push(obj);
    }
}

/* TODO extract common logic to MemAllocate */
int
MemPoolMalloc::getStats(MemPoolStats * stats, int accumulate)
{
    if (!accumulate)    /* need skip memset for GlobalStats accumulation */
        memset(stats, 0, sizeof(MemPoolStats));

    stats->pool = this;
    stats->label = objectType();
    stats->meter = &meter;
    stats->obj_size = obj_size;
    stats->chunk_capacity = 0;

    stats->chunks_alloc += 0;
    stats->chunks_inuse += 0;
    stats->chunks_partial += 0;
    stats->chunks_free += 0;

    stats->items_alloc += meter.alloc.currentLevel();
    stats->items_inuse += meter.inuse.currentLevel();
    stats->items_idle += meter.idle.currentLevel();

    stats->overhead += sizeof(MemPoolMalloc) + strlen(objectType()) + 1;

    return meter.inuse.currentLevel();
}

int
MemPoolMalloc::getInUseCount()
{
    return meter.inuse.currentLevel();
}

MemPoolMalloc::MemPoolMalloc(char const *aLabel, size_t aSize) : MemImplementingAllocator(aLabel, aSize)
{
}

MemPoolMalloc::~MemPoolMalloc()
{
    assert(meter.inuse.currentLevel() == 0);
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

