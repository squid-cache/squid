/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGE_POOL_H
#define SQUID_IPC_MEM_PAGE_POOL_H

#include "ipc/mem/PageStack.h"
#include "ipc/mem/Pointer.h"

namespace Ipc {

namespace Mem {

/// Atomic container of shared memory pages. Implemented using a collection of
/// Segments, each with a PageStack index of free pages. All pools must be
/// created by a single process.
class PagePool {
public:
    typedef Ipc::Mem::Owner<PageStack> Owner;

    static Owner *Init(const char *const id, const unsigned int capacity, const size_t pageSize);

    PagePool(const char *const id);

    unsigned int capacity() const { return pageIndex->capacity(); }
    size_t pageSize() const { return pageIndex->pageSize(); }
    /// lower bound for the number of free pages
    unsigned int size() const { return pageIndex->size(); }

    /// sets page ID and returns true unless no free pages are found
    bool get(PageId &page) { return pageIndex->pop(page); }
    /// makes identified page available as a free page to future get() callers
    void put(PageId &page) { return pageIndex->push(page); }
    /// converts page handler into a temporary writeable shared memory pointer
    void *pagePointer(const PageId &page);

private:
    Ipc::Mem::Pointer<PageStack> pageIndex; ///< free pages index
    char *theBuf; ///< pages storage
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_POOL_H
