/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_MEM_STATS_H
#define SQUID__SRC_MEM_STATS_H

#include "mem/forward.h"

namespace Mem
{

/// summary of one or more Memory Pool contents
class PoolStats
{
public:
    AllocatorBase *pool = nullptr;
    const char *label = nullptr;
    PoolMeter *meter = nullptr;

    size_t obj_size = 0;
    size_t chunk_capacity = 0;
    size_t chunk_size = 0;

    struct counts_ {
        size_t alloc = 0; ///< number of objects currently allocated
        size_t inuse = 0; ///< number of objects assigned for use
        size_t idle = 0; ///< number of allocations awaiting use
        size_t partial = 0; ///< chunks partially used (TODO: merge with 'idle')
        size_t free = 0; ///< number of free allocations
    } chunks, items;

    size_t overhead = 0;
};

} // namespace Mem

#endif /* SQUID__SRC_MEM_STATS_H */
