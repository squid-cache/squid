/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGES_H
#define SQUID_IPC_MEM_PAGES_H

namespace Ipc {

namespace Mem {

class PageId;

/// initializes and configures shared memory [pools] for all kids
void Init();

/// attaches this kid to the already configured shared memory [pools]
void Attach();


/* Single page manipulation */

/// sets page ID and returns true unless no free pages are found
bool GetPage(PageId &page);

/// makes identified page available as a free page to future GetPage() callers
void PutPage(const PageId &page);

/// converts page handler into a temporary writeable shared memory pointer
void *PagePointer(const PageId &page);


/* Limits and statistics */

/// the total number of shared memory bytes that can be in use at any time
uint64_t Limit();

/// approximate total number of shared memory bytes used now
uint64_t Level();

/// approximate total number of shared memory bytes we can allocate now
inline uint64_t Available() { return Limit() - Level(); }

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGES_H
