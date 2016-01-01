/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_PAGE_STACK_H
#define SQUID_IPC_MEM_PAGE_STACK_H

#include "ipc/mem/FlexibleArray.h"

#include <atomic>

namespace Ipc
{

namespace Mem
{

class PageId;

/// Atomic container of "free" page numbers inside a single SharedMemory space.
/// Assumptions: all page numbers are unique, positive, have an known maximum,
/// and can be temporary unavailable as long as they are never trully lost.
class PageStack
{
public:
    typedef uint32_t Value; ///< stack item type (a free page number)

    PageStack(const uint32_t aPoolId, const unsigned int aCapacity, const size_t aPageSize);

    unsigned int capacity() const { return theCapacity; }
    size_t pageSize() const { return thePageSize; }
    /// lower bound for the number of free pages
    unsigned int size() const { return max(0, theSize.load()); }

    /// sets value and returns true unless no free page numbers are found
    bool pop(PageId &page);
    /// makes value available as a free page number to future pop() callers
    void push(PageId &page);

    bool pageIdIsValid(const PageId &page) const;

    /// total shared memory size required to share
    static size_t SharedMemorySize(const uint32_t aPoolId, const unsigned int capacity, const size_t pageSize);
    size_t sharedMemorySize() const;

    /// shared memory size required only by PageStack, excluding
    /// shared counters and page data
    static size_t StackSize(const unsigned int capacity);
    size_t stackSize() const;

private:
    /// stack index and size type (may temporary go negative)
    typedef int Offset;

    // these help iterate the stack in search of a free spot or a page
    Offset next(const Offset idx) const { return (idx + 1) % theCapacity; }
    Offset prev(const Offset idx) const { return (theCapacity + idx - 1) % theCapacity; }

    const uint32_t thePoolId; ///< pool ID
    const Offset theCapacity; ///< stack capacity, i.e. theItems size
    const size_t thePageSize; ///< page size, used to calculate shared memory size
    /// lower bound for the number of free pages (may get negative!)
    std::atomic<Offset> theSize;

    /// last readable item index; just a hint, not a guarantee
    std::atomic<Offset> theLastReadable;
    /// first writable item index; just a hint, not a guarantee
    std::atomic<Offset> theFirstWritable;

    typedef std::atomic<Value> Item;
    Ipc::Mem::FlexibleArray<Item> theItems; ///< page number storage
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_STACK_H

