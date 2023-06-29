/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/Allocator.h"
#include "mem/AllocatorProxy.h"
#include "mem/Pool.h"
#include "mem/Stats.h"

void *
Mem::AllocatorProxy::alloc()
{
    return getAllocator()->alloc();
}

void
Mem::AllocatorProxy::freeOne(void *address)
{
    getAllocator()->freeOne(address);
    /* TODO: check for empty, and if so, if the default type has altered,
     * switch
     */
}

Mem::Allocator *
Mem::AllocatorProxy::getAllocator() const
{
    if (!theAllocator) {
        theAllocator = MemPools::GetInstance().create(objectType(), size);
        theAllocator->zeroBlocks(doZero);
    }
    return theAllocator;
}

int
Mem::AllocatorProxy::inUseCount() const
{
    if (!theAllocator)
        return 0;
    else
        return theAllocator->getInUseCount();
}

void
Mem::AllocatorProxy::zeroBlocks(bool doIt)
{
    getAllocator()->zeroBlocks(doIt);
}

Mem::PoolMeter const &
Mem::AllocatorProxy::getMeter() const
{
    return getAllocator()->meter;
}

size_t
Mem::AllocatorProxy::getStats(PoolStats &stats)
{
    return getAllocator()->getStats(stats);
}

