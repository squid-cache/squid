/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_ALLOCATOR_H
#define SQUID_SRC_MEM_ALLOCATOR_H

#include "base/TypeTraits.h"
#include "mem/forward.h"
#include "mem/Meter.h"

namespace Mem
{

/// An interface for memory allocators that deal with fixed-size objects.
/// Allocators may optimize repeated de/allocations using memory pools.
class Allocator : public Interface
{
public:
    /// Flush counters to 'meter' after flush limit allocations
    static const size_t FlushLimit = 1000;

    explicit Allocator(const char * const aLabel, const size_t sz):
        label(aLabel),
        objectSize(RoundedSize(sz))
    {}

    // TODO make this method const
    /**
     * fill the given object with statistical data about pool
     * \returns Number of objects in use, ie. allocated.
     */
    virtual size_t getStats(PoolStats &) = 0;

    /// provide (and reserve) memory suitable for storing one object
    void *alloc() {
        if (++count.allocs == FlushLimit)
            flushCounters();
        return allocate();
    }

    /// return memory reserved by alloc()
    void freeOne(void *obj) {
        assert(obj != nullptr);
        (void) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(obj, objectSize);
        deallocate(obj);
        ++count.freed;
    }

    // XXX: \deprecated use label directly
    virtual char const *objectType() const { return label; }

    /// the difference between the number of alloc() and freeOne() calls
    virtual int getInUseCount() = 0;

    /// \see doZero
    void zeroBlocks(const bool doIt) { doZero = doIt; }

    // XXX: \deprecated use getInUseCount()
    int inUseCount() { return getInUseCount(); }

    /// XXX: Misplaced -- not all allocators have a notion of a "chunk". See MemPoolChunked.
    virtual void setChunkSize(size_t) {}

    virtual bool idleTrigger(int shift) const = 0;

    virtual void clean(time_t maxage) = 0;

    /**
     * Flush temporary counter values into the statistics held in 'meter'.
     * Performs some CPU intensive calculations which have been deferred for performance.
     */
    void flushCounters() {
        if (count.freed) {
            meter.gb_freed.update(count.freed, objectSize);
            count.freed = 0;
        }
        if (count.allocs) {
            meter.gb_allocated.update(count.allocs, objectSize);
            count.allocs = 0;
        }
        if (count.saved_allocs) {
            meter.gb_saved.update(count.saved_allocs, objectSize);
            count.saved_allocs = 0;
        }
    }

    /**
     * \param minSize Minimum size needed to be allocated.
     * \retval n Smallest size divisible by sizeof(void*)
     */
    static size_t RoundedSize(const size_t minSize) { return ((minSize + sizeof(void*) - 1) / sizeof(void*)) * sizeof(void*); }

public:

    /** Temporary counters for performance optimization.
     *
     * Counts allocator activity until a flushCounters() gets
     * triggered to move the values into the 'meter' statistics.
     *
     * Specific Optimizations:
     * \li Objects have fixed-size,
     *     so all calculations about bytes can be deferred.
     * \li Objects pooled (if any) can be inferred,
     *     so saved_free counting is unnecessary.
     * \li Objects actively in use (if any) can be inferred,
     *     so no inuse_count management on alloc() or freeOne().
     */
    struct FastCounter {
       size_t allocs = 0; ///< accumulated calls to alloc()
       size_t saved_allocs = 0; ///< alloc() calls which re-used an idle object
       size_t freed = 0; ///< accumulated calls to freeOne()
    } count;

    /// brief description of objects returned by alloc()
    const char *label;

    /// the size (in bytes) of objects managed by this allocator
    const size_t objectSize;

    /// statistics tracked for this allocator
    PoolMeter meter;

protected:
    /// \copydoc void *alloc()
    virtual void *allocate() = 0;
    /// \copydoc void freeOne(void *)
    virtual void deallocate(void *) = 0;

    /**
     * Whether to zero memory on initial allocation and on return to the pool.
     *
     * We do this on some pools because many object constructors are/were incomplete
     * and we are afraid some code may use the object after free.
     * When possible, set this to false to avoid zeroing overheads.
     */
    bool doZero = true;
};

} // namespace Mem

#endif /* SQUID_SRC_MEM_ALLOCATOR_H */
