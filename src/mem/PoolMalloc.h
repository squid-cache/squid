/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_POOLMALLOC_H
#define SQUID_SRC_MEM_POOLMALLOC_H

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

#include "mem/Allocator.h"

#include <stack>

/// \ingroup MemPoolsAPI
class MemPoolMalloc : public Mem::Allocator
{
public:
    MemPoolMalloc(char const *label, size_t aSize);
    ~MemPoolMalloc() override;

    /* Mem::Allocator API */
    size_t getStats(Mem::PoolStats &) override;
    bool idleTrigger(int) const override;
    void clean(time_t) override;

protected:
    /* Mem::Allocator API */
    void *allocate() override;
    void deallocate(void *) override;

private:
    std::stack<void *> freelist;
};

#endif /* SQUID_SRC_MEM_POOLMALLOC_H */

