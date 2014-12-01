#include "squid.h"
#include "mem/AllocatorProxy.h"
#include "mem/Pool.h"

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

MemAllocator *
Mem::AllocatorProxy::getAllocator() const
{
    if (!theAllocator)
        theAllocator = MemPools::GetInstance().create(objectType(), size);
    return theAllocator;
}

int
Mem::AllocatorProxy::inUseCount() const
{
    if (!theAllocator)
        return 0;
    else
        return memPoolInUseCount(theAllocator);
}

MemPoolMeter const &
Mem::AllocatorProxy::getMeter() const
{
    return getAllocator()->getMeter();
}

int
Mem::AllocatorProxy::getStats(MemPoolStats * stats)
{
    return getAllocator()->getStats(stats);
}
