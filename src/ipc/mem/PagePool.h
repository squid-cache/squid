/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGE_POOL_H
#define SQUID_IPC_MEM_PAGE_POOL_H

#include "ipc/mem/PageStack.h"
#include "ipc/mem/Segment.h"

namespace Ipc {

namespace Mem {

class PageId;

/// Atomic container of shared memory pages. Implemented using a collection of
/// Segments, each with a PageStack index of free pages. All pools must be
/// created by a single process.
class PagePool {
public:
    /// creates a new shared page pool that can hold up to capacity pages of pageSize size
    PagePool(const String &id, const unsigned int capacity, const size_t pageSize);
    /// attaches to the identified shared page pool
    PagePool(const String &id);
    /// unlinks shared memory segments
    static void Unlink(const String &id);

    unsigned int capacity() const { return shared->theCapacity; }
    /// lower bound for the number of free pages
    unsigned int size() const { return pageIndex.size(); }
    size_t pageSize() const { return shared->thePageSize; }

    /// sets page ID and returns true unless no free pages are found
    bool get(PageId &page);
    /// makes identified page available as a free page to future get() callers
    void put(PageId &page);
    /// converts page handler into a temporary writeable shared memory pointer
    void *pagePointer(const PageId &page);

private:
    inline bool pageIdIsValid(const PageId &page) const;

    struct Shared {
        Shared(const unsigned int aCapacity, const size_t aPageSize);

        /// total shared memory size required to share
        static off_t MemSize(const unsigned int capacity, const size_t pageSize);

        const unsigned int theId; ///< pool id
        const unsigned int theCapacity; ///< number of pages in the pool
        const size_t thePageSize; ///< page size

        // TODO: add padding to make pages system page-aligned?
        char theBuf[]; ///< pages storage
    };

    PageStack pageIndex; ///< free pages index
    Segment shm; ///< shared memory segment to store metadata (and pages)
    Shared *shared; ///< our metadata and page storage, shared among all pool users
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_POOL_H
