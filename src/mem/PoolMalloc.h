/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _MEM_POOL_MALLOC_H_
#define _MEM_POOL_MALLOC_H_

/**
 \defgroup MemPoolsAPI  Memory Management (Memory Pool Allocator)
 \ingroup Components
 *
 *\par
 *  MemPools are a pooled memory allocator running on top of malloc(). It's
 *  purpose is to reduce memory fragmentation and provide detailed statistics
 *  on memory consumption.
 *
 \par
 *  Preferably all memory allocations in Squid should be done using MemPools
 *  or one of the types built on top of it (i.e. cbdata).
 *
 \note Usually it is better to use cbdata types as these gives you additional
 *     safeguards in references and typechecking. However, for high usage pools where
 *     the cbdata functionality of cbdata is not required directly using a MemPool
 *     might be the way to go.
 */

#include "mem/Pool.h"

#include <stack>

/// \ingroup MemPoolsAPI
class MemPoolMalloc : public MemImplementingAllocator
{
public:
    MemPoolMalloc(char const *label, size_t aSize);
    ~MemPoolMalloc();
    virtual bool idleTrigger(int shift) const;
    virtual void clean(time_t maxage);

    /**
     \param stats   Object to be filled with statistical data about pool.
     \retval        Number of objects in use, ie. allocated.
     */
    virtual int getStats(MemPoolStats * stats, int accumulate);

    virtual int getInUseCount();
protected:
    virtual void *allocate();
    virtual void deallocate(void *, bool aggressive);
private:
    std::stack<void *> freelist;
};

#endif /* _MEM_POOL_MALLOC_H_ */

