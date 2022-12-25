/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/AllocatorProxy.h"
#include "mem/Meter.h"

void *
memAllocBuf(const size_t netSize, size_t * const grossSize)
{
    if (grossSize)
        *grossSize = netSize;
    return xmalloc(netSize);
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

