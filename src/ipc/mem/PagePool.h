/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGE_POOL_H
#define SQUID_IPC_MEM_PAGE_POOL_H

#include "ipc/mem/Page.h"
#include "ipc/mem/Segment.h"

namespace Ipc {

namespace Mem {

/// Atomic container of shared memory pages. Implemented using a collection of
/// Segments, each with a PageStack index of free pages.
class PagePool {
public:
    /// creates a new shared page pool that can hold up to capacity pages
    PagePool(const String &id, const unsigned int capacity);
    /// attaches to the identified shared page pool
    PagePool(const String &id);

    /// sets page ID and returns true unless no free pages are found
    bool get(PageId &page);
    /// makes identified page available as a free page to future get() callers
    void put(const PageId &page);

private:
    Segment meta; ///< shared memory segment to store our metadata
    /// TODO: Shared *shared; ///< our metadata, shared among all pool users

    /// TODO: typedef collection<Segment*> Store; ///< storage for pages
    /// TODO: Store store; ///< pages (with free page indexes)
};

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_POOL_H
