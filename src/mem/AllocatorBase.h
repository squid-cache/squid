/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_ALLOCATORBASE_H
#define SQUID_SRC_MEM_ALLOCATORBASE_H

#include "mem/forward.h"

namespace Mem
{

/**
 * Basic API definition for memory pooling allocators.
 *
 * A pool is a [growing] space for objects of the same size
 */
class AllocatorBase
{
public:
    AllocatorBase(char const *aLabel) : label(aLabel) {}
    virtual ~AllocatorBase() {}

    /**
     * fill the given object with statistical data about pool
     * \returns Number of objects in use, ie. allocated.
     */
    virtual int getStats(MemPoolStats *, int accumulate = 0) = 0;

    virtual PoolMeter const &getMeter() const = 0;

    /// allocate one element from the pool
    virtual void *alloc() = 0;

    /// free a element allocated by AllocatorBase::alloc()
    virtual void freeOne(void *) = 0;

    /// get a display label for objects in this pool
    virtual char const *objectType() const { return label; }

    /// the size (in bytes) of objects managed by this allocator
    virtual size_t objectSize() const = 0;

    /// the number of objects currently allocated
    virtual int getInUseCount() = 0;

    /// \see doZero
    void zeroBlocks(bool doIt) {doZero = doIt;}

    int inUseCount() { return getInUseCount(); } // XXX: drop redundant?

    /**
     * Allows you tune chunk size of pooling. Objects are allocated in chunks
     * instead of individually. This conserves memory, reduces fragmentation.
     * Because of that memory can be freed also only in chunks. Therefore
     * there is tradeoff between memory conservation due to chunking and free
     * memory fragmentation.
     *
     * \note  As a general guideline, increase chunk size only for pools that keep
     *        very many items for relatively long time.
     */
    virtual void setChunkSize(size_t) {}

    /**
     * \param minSize Minimum size needed to be allocated.
     * \retval n Smallest size divisible by sizeof(void*)
     */
    static size_t RoundedSize(size_t minSize);

protected:
    /**
     * Whether to zero memory on initial allocation and on return to the pool.
     *
     * We do this on some pools because many object constructors are/were incomplete
     * and we are afraid some code may use the object after free.
     * These probems are becoming less common, so when possible set this to false.
     */
    bool doZero = true;

private:
    const char *label = nullptr;
};

} // namespace Mem

#endif /* SQUID_SRC_MEM_ALLOCATORBASE_H */
