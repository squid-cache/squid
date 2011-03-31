/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_MEM_PAGE_H
#define SQUID_IPC_MEM_PAGE_H

#if HAVE_IOSFWD
#include <iosfwd>
#endif

namespace Ipc {

namespace Mem {

/// Shared memory page identifier, address, or handler
class PageId {
public:
    PageId(): segment(0), number(0) {}

    // uint32_t pool; ///< page pool ID within Squid; unused for now
    uint32_t segment; ///< memory segment ID within the pool
    uint32_t number; ///< page number within the segment
};

/// writes page address (e.g., "sh_page5.3"), for debugging
std::ostream &operator <<(std::ostream &os, const PageId &page);

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_H
