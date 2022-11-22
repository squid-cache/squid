/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_ALLOCATOR_H
#define SQUID_SRC_MEM_ALLOCATOR_H

#include "base/TypeTraits.h"
#include "mem/forward.h"

namespace Mem
{

/// An interface for memory allocators that deal with fixed-size objects.
/// Allocators may optimize repeated de/allocations using memory pools.
class Allocator : public Interface
{
public:
    explicit Allocator(const char * const aLabel): label(aLabel) {}

    // TODO make this method const
    /**
     * fill the given object with statistical data about pool
     * \returns Number of objects in use, ie. allocated.
     */
    virtual int getStats(MemPoolStats *) = 0;

    virtual PoolMeter const &getMeter() const = 0;

    /// provide (and reserve) memory suitable for storing one object
    virtual void *alloc() = 0;

    /// return memory reserved by alloc()
    virtual void freeOne(void *) = 0;

    /// brief description of objects returned by alloc()
    virtual char const *objectType() const { return label; }

    /// the size (in bytes) of objects managed by this allocator
    virtual size_t objectSize() const = 0;

    /// the difference between the number of alloc() and freeOne() calls
    virtual int getInUseCount() = 0;

    /// \see doZero
    void zeroBlocks(const bool doIt) { doZero = doIt; }

    int inUseCount() { return getInUseCount(); } // XXX: drop redundant?

    /// XXX: Misplaced -- not all allocators have a notion of a "chunk". See MemPoolChunked.
    virtual void setChunkSize(size_t) {}

    /**
     * \param minSize Minimum size needed to be allocated.
     * \retval n Smallest size divisible by sizeof(void*)
     */
    static size_t RoundedSize(const size_t minSize) { return ((minSize + sizeof(void*) - 1) / sizeof(void*)) * sizeof(void*); }

protected:
    /**
     * Whether to zero memory on initial allocation and on return to the pool.
     *
     * We do this on some pools because many object constructors are/were incomplete
     * and we are afraid some code may use the object after free.
     * When possible, set this to false to avoid zeroing overheads.
     */
    bool doZero = true;

private:
    const char *label = nullptr;
};

} // namespace Mem

#endif /* SQUID_SRC_MEM_ALLOCATOR_H */
