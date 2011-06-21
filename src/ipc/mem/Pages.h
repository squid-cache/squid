/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGES_H
#define SQUID_IPC_MEM_PAGES_H

namespace Ipc {

namespace Mem {

class PageId;

/* Single page manipulation */

/// sets page ID and returns true unless no free pages are found
bool GetPage(PageId &page);

/// makes identified page available as a free page to future GetPage() callers
void PutPage(PageId &page);

/// converts page handler into a temporary writeable shared memory pointer
char *PagePointer(const PageId &page);


/* Limits and statistics */

/// the total number of shared memory pages that can be in use at any time
size_t PageLimit();

/// the total number of shared memory pages for memory cache that can be in
/// use at any time
size_t CachePageLimit();

/// the total number of shared memory pages for IPC IO that can be in
/// use at any time
size_t IoPageLimit();

/// approximate total number of shared memory pages used now
size_t PageLevel();

/// approximate total number of shared memory pages for memory cache used now
size_t CachePageLevel();

/// approximate total number of shared memory pages for IPC IO used now
size_t IoPageLevel();

/// approximate total number of shared memory pages we can allocate now
inline size_t PagesAvailable() { return PageLimit() - PageLevel(); }

/// approximate total number of shared memory pages for memory cache we can
/// allocate now
inline size_t CachePagesAvailable() { return CachePageLimit() - CachePageLevel(); }

/// approximate total number of shared memory pages for IPC IO we can allocate now
inline size_t IoPagesAvailable() { return IoPageLimit() - IoPageLevel(); }

/// returns page size in bytes; all pages are assumed to be the same size
size_t PageSize();

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGES_H
