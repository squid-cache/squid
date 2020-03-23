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

class IdSetPosition;
typedef enum { dirNone, dirLeft, dirRight, dirEnd } IdSetNavigationDirection;

/// basic IdSet storage parameters, extracted here to keep them constant
class IdSetMeasurements
{
public:
    /// we need to fit two size_type counters into one 64-bit lockless atomic
    typedef uint32_t size_type;

    explicit IdSetMeasurements(size_type capacity);

    /// the maximum number of pages our tree is allowed to store
    size_type capacity = 0;

    /// the number of leaf nodes that satisfy capacity requirements
    size_type requestedLeafNodeCount = 0;

    size_type treeHeight = 0; ///< total number of levels, including the leaf level
    size_type leafNodeCount = 0; ///< the number of nodes at the leaf level
    size_type innerLevelCount = 0; ///< all levels except the leaf level

    /// the total number of nodes at all levels
    size_type nodeCount() const { return leafNodeCount ? leafNodeCount*2 -1 : 0; }
};

/// a shareable set of positive uint32_t IDs with O(1) insertion/removal ops
class IdSet
{
public:
    using size_type = IdSetMeasurements::size_type;
    using Position = IdSetPosition;
    using NavigationDirection = IdSetNavigationDirection;

    /// memory size required to store a tree with the given capacity
    static size_t MemorySize(size_type capacity);

    explicit IdSet(size_type capacity);

    /// populates the allocated tree with the requested capacity IDs
    /// optimized to run without atomic protection
    void makeFullBeforeSharing();

    /// finds/extracts (into the given `id`) an ID value and returns true
    /// \retval false no IDs are left
    bool pop(size_type &id);

    /// makes `id` value available to future pop() callers
    void push(size_type id);

    const IdSetMeasurements measurements;

private:
    typedef uint64_t Node; ///< either leaf or intermediate node
    typedef std::atomic<Node> StoredNode; ///< a Node stored in shared memory

    /* optimization: these initialization methods bypass atomic protections */
    void fillAllNodes();
    void truncateExtras();
    Node *valueAddress(Position);
    size_type innerTruncate(Position pos, NavigationDirection dir, size_type toSubtract);
    void leafTruncate(Position pos, size_type idsToKeep);

    void innerPush(Position, NavigationDirection);
    NavigationDirection innerPop(Position);

    void leafPush(Position, size_type id);
    size_type leafPop(Position);

    Position ascend(Position);
    Position descend(Position, NavigationDirection);

    StoredNode &nodeAt(Position);

    /// the entire binary tree flattened into an array
    FlexibleArray<StoredNode> nodes_;
    // No more data members should follow! See FlexibleArray<> for details.
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
    // XXX: theFoo members look misplaced due to messy separation of PagePool
    // (which should support multiple Segments but does not) and PageStack
    // (which should not calculate the Segment size but does) duties.
    const PoolId thePoolId; ///< pool ID
    const PageCount capacity_; ///< the maximum number of pages
    const size_t thePageSize; ///< page size, used to calculate shared memory size
    /// a lower bound for the number of free pages (for debugging purposes)
    std::atomic<PageCount> size_;

    IdSet ids_; ///< free pages (valid with positive capacity_)
    // No more data members should follow! See IdSet for details.
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_STACK_H

