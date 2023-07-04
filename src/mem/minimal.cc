/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/AllocatorProxy.h"
#include "mem/forward.h"

/// The number of currently alive objects (poor man's meter.alloc=meter.inuse).
/// Technically, this is supposed to be a per-allocator statistics, but
/// AllocatorProxy is not a Mem::Allocator so we maintain a global counter
/// instead. We probably do not have to maintain this statistics at all.
static int Alive = 0;

void *
Mem::AllocatorProxy::alloc()
{
    const auto memory = doZero ? xcalloc(1, size) : xmalloc(size);
    ++Alive;
    return memory;
}

void
Mem::AllocatorProxy::freeOne(void *memory) {
    xfree(memory);
    --Alive;
}

int
Mem::AllocatorProxy::inUseCount() const
{
    return Alive;
}

size_t
Mem::AllocatorProxy::getStats(PoolStats &)
{
    return Alive;
}

void *
memAllocBuf(const size_t netSize, size_t * const grossSize)
{
    *grossSize = netSize;
    return xcalloc(1, netSize);
}

void *
memReallocBuf(void * const oldBuf, const size_t netSize, size_t * const grossSize)
{
    *grossSize = netSize;
    return xrealloc(oldBuf, netSize);
}

void
memFree(void *memory, int)
{
    xfree(memory);
}

void *
memAllocString(const size_t netSize, size_t * const grossSize)
{
    return memAllocBuf(netSize, grossSize);
}

void
memFreeString(size_t, void *memory)
{
    xfree(memory);
}

void *
memAllocRigid(const size_t netSize)
{
    return xmalloc(netSize);
}

void
memFreeRigid(void * const buf, size_t)
{
    xfree(buf);
}

void
memFreeBuf(size_t, void * const buf)
{
    xfree(buf);
}

static void
myFree(void * const buf)
{
    xfree(buf);
}

FREE *
memFreeBufFunc(size_t)
{
    return &myFree;
}

