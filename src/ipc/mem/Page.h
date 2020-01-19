/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_PAGE_H
#define SQUID_IPC_MEM_PAGE_H

#include "ipc/mem/forward.h"

#include <iosfwd>

namespace Ipc
{

namespace Mem
{

/// Shared memory page identifier, address, or handler
class PageId
{
public:
    PageId(): pool(0), number(0), purpose(maxPurpose) {}

    /// true if and only if both critical components have been initialized
    bool set() const { return pool && number; }

    // safer than bool which would enable silent casts to int
    typedef const uint32_t PageId::*SaferBool;
    operator SaferBool() const { return set() ? &PageId::number : NULL; }

    /// The ID of a PagePool (and/or PageStack) this page belongs to.
    /// Positive values are (ab)used to detect in-use pages. See set().
    /// Eventually, they may identify a PageStack in a multi-segment PagePool.
    /// These IDs also distinguish page pools/stacks in debugging logs.
    PoolId pool;

    // uint32_t segment; ///< memory segment ID within the pool; unused for now
    uint32_t number; ///< page number within the segment

    enum Purpose { cachePage, ioPage, maxPurpose };
    Purpose purpose; ///< page purpose
};

/// writes page address (e.g., "sh_page5.3"), for debugging
std::ostream &operator <<(std::ostream &os, const PageId &page);

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGE_H

