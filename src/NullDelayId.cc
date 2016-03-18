/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

#if USE_DELAY_POOLS
#include "DelayPools.h"
#include "NullDelayId.h"

void *
NullDelayId::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (NullDelayId);
    return ::operator new (size);
}

void
NullDelayId::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (NullDelayId);
    ::operator delete (address);
}

#endif /* USE_DELAY_POOLS */

