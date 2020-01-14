/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_PAGE_STACK_H
#define SQUID_IPC_MEM_PAGE_STACK_H

#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/forward.h"

#include <atomic>
#include <limits>

namespace Ipc
{

namespace Mem
{

class PageId;

/// reflects the dual nature of PageStack storage:
/// - for free pages, this is a pointer to the next free page
/// - for used pages, this is a "used page" marker
class PageStackStorageSlot
{
public:
    // We are using uint32_t for Pointer because PageId::number is uint32_t.
    // PageId::number should probably be uint64_t to accommodate caches with
    // page numbers exceeding UINT32_MAX.
    typedef uint32_t PointerOrMarker;
    typedef PointerOrMarker Pointer;
    typedef PointerOrMarker Marker;

    /// represents a nil next slot pointer
    static const Pointer NilPtr = std::numeric_limits<PointerOrMarker>::max();
    /// marks a slot of a used (i.e. take()n) page
    static const Marker TakenPage = std::numeric_limits<PointerOrMarker>::max() - 1;
    static_assert(TakenPage != NilPtr, "magic PointerOrMarker values do not clash");

    explicit PageStackStorageSlot(const Pointer nxt = NilPtr): nextOrMarker(nxt) {}

    /// returns a (possibly nil) pointer to the next free page
    Pointer next() const { return nextOrMarker.load(); }

    /// marks our page as used
    void take();

    /// marks our page as free, to be used before the given `nxt` page;
    /// also checks that the slot state matches the caller expectations
    void put(const PointerOrMarker expected, const Pointer nxt);

private:
    std::atomic<PointerOrMarker> nextOrMarker;
};

/// Atomic container of "free" PageIds. Detects (some) double-free bugs.
/// Assumptions: All page numbers are unique, positive, with a known maximum.
/// A pushed page may not become available immediately but is never truly lost.
class PageStack
{
public:
    typedef std::atomic<size_t> Levels_t;

    // XXX: The actual type may have been on PagePool::Init() but may conflict
    // with PageLimit(), StoreMapSliceId, Rock::SwapDirRr::slotLimitActual(),
    // Rock::SlotId, PageId::number, etc.
    /// the number of (free and/or used) pages in a stack
    typedef unsigned int PageCount;

    PageStack(const PoolId aPoolId, const PageCount aCapacity, const size_t aPageSize);

    PageCount capacity() const { return capacity_; }
    size_t pageSize() const { return thePageSize; }
    /// an approximate number of free pages
    PageCount size() const { return size_.load(); }

    /// sets value and returns true unless no free page numbers are found
    bool pop(PageId &page);
    /// makes value available as a free page number to future pop() callers
    void push(PageId &page);

    bool pageIdIsValid(const PageId &page) const;

    /// total shared memory size required to share
    static size_t SharedMemorySize(const PoolId aPoolId, const PageCount capacity, const size_t pageSize);
    size_t sharedMemorySize() const;

    /// shared memory size required only by PageStack, excluding
    /// shared counters and page data
    static size_t StackSize(const PageCount capacity);
    size_t stackSize() const;

    /// \returns the number of padding bytes to align PagePool::theLevels array
    static size_t LevelsPaddingSize(const PageCount capacity);
    size_t levelsPaddingSize() const { return LevelsPaddingSize(capacity_); }

    /**
     * The following functions return PageStack IDs for the corresponding
     * PagePool or a similar PageStack user. The exact values are unimportant,
     * but their uniqueness and stability eases debugging.
     */

    /// stack of free cache_mem slot positions
    static PoolId IdForMemStoreSpace() { return 10; }
    /// multipurpose PagePool of shared memory pages
    static PoolId IdForMultipurposePool() { return 200; } // segments could use 2xx
    /// stack of free rock cache_dir slot numbers
    static PoolId IdForSwapDirSpace(const int dirIdx) { return 900 + dirIdx + 1; }

private:
    using Slot = PageStackStorageSlot;

    // XXX: theFoo members look misplaced due to messy separation of PagePool
    // (which should support multiple Segments but does not) and PageStack
    // (which should not calculate the Segment size but does) duties.
    const PoolId thePoolId; ///< pool ID
    const PageCount capacity_; ///< the maximum number of pages
    const size_t thePageSize; ///< page size, used to calculate shared memory size
    /// a lower bound for the number of free pages (for debugging purposes)
    std::atomic<PageCount> size_;

    /// the index of the first free stack element or nil
    std::atomic<Slot::Pointer> head_;

    /// slots indexed using their page number
    Ipc::Mem::FlexibleArray<Slot> slots_;
    // No more data members should follow! See Ipc::Mem::FlexibleArray<> for details.
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_STACK_H

