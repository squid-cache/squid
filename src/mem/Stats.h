/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

class PoolStats
{
public:
    Allocator *pool = nullptr;
    const char *label = nullptr;
    PoolMeter *meter = nullptr;
    int obj_size = 0;
    int chunk_capacity = 0;
    int chunk_size = 0;

    int chunks_alloc = 0;
    int chunks_inuse = 0;
    int chunks_partial = 0;
    int chunks_free = 0;

    int items_alloc = 0;
    int items_inuse = 0;
    int items_idle = 0;

    int overhead = 0;
};

/**
 * Fills a Mem::PoolStats with statistical data about overall
 * usage for all pools.
 *
 * \return Number of pools that have at least one object in use.
 *        Ie. number of dirty pools.
 */
extern size_t GlobalStats(PoolStats &);

} // namespace Mem

#endif /* SQUID__SRC_MEM_STATS_H */
