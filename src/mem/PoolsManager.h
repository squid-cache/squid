/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_MEM_POOLSMANAGER_H
#define SQUID__SRC_MEM_POOLSMANAGER_H

#include "mem/forward.h"

#include <algorithm>
#include <list>

namespace Mem
{

class PoolsManager
{
public:
    PoolsManager();

    static PoolsManager &GetInstance();

    Mem::AllocatorMetrics *create(const char *label, size_t objectSize);

    /**
     * Sets upper limit in bytes to amount of free ram kept in pools. This is
     * not strict upper limit, but a hint. When pools are over this limit,
     * totally free chunks are immediately considered for release. Otherwise
     * only chunks that have not been referenced for a long time are checked.
     */
    void setIdleLimit(ssize_t limit) {mem_idle_limit = limit;}
    ssize_t idleLimit() const {return mem_idle_limit;}

    void setDefaultPoolChunking(bool const &value) {defaultIsChunked = value;}

    /**
     * \par
     * Main cleanup handler. For pools to stay within upper idle limits,
     * this function needs to be called periodically, preferably at some
     * constant rate, eg. from Squid event. It looks through all pools and
     * chunks, cleans up internal states and checks for releasable chunks.
     *
     * \par
     * Between the calls to this function objects are placed onto internal
     * cache instead of returning to their home chunks, mainly for speedup
     * purpose. During that time state of chunk is not known, it is not
     * known whether chunk is free or in use. This call returns all objects
     * to their chunks and restores consistency.
     *
     * \par
     * Should be called relatively often, as it sorts chunks in suitable
     * order as to reduce free memory fragmentation and increase chunk
     * utilisation.
     * Suitable frequency for cleanup is in range of few tens of seconds to
     * few minutes, depending of memory activity.
     *
     * TODO: DOCS: Re-write this shorter!
     *
     * \param maxage   Release all totally idle chunks that
     *                 have not been referenced for maxage seconds.
     */
    void clean(time_t maxage);

    void flushMeters();

    /// interface to register pools for memory accounting
    void registerPool(Mem::AllocatorMetrics *p) {
        pools.push_back(p);
    }
    void unregisterPool(const Mem::AllocatorMetrics *p) {
        std::remove(pools.begin(),pools.end(),p);
    }

public:
    std::list<Mem::AllocatorMetrics *> pools;

    ssize_t mem_idle_limit = (2 << 20); // 2MB default

    /**
     * Change the default value of defaultIsChunked to override
     * all pools - including those used before main() starts where
     * MemPools::GetInstance().setDefaultPoolChunking() can be called.
     */
    bool defaultIsChunked = false;
};

} // namespace Mem

#endif /* SQUID__SRC_MEM_POOLSMANAGER_H */
