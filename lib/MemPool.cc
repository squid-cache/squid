
/*
 * $Id$
 *
 * DEBUG: section 63    Low Level Memory Pool Management
 * AUTHOR: Alex Rousskov, Andres Kroonmaa, Robert Collins
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/*
 * Old way:
 *   xmalloc each item separately, upon free stack into idle pool array.
 *   each item is individually malloc()ed from system, imposing libmalloc
 *   overhead, and additionally we add our overhead of pointer size per item
 *   as we keep a list of pointer to free items.
 *
 * Chunking:
 *   xmalloc Chunk that fits at least MEM_MIN_FREE (32) items in an array, but
 *   limit Chunk size to MEM_CHUNK_MAX_SIZE (256K). Chunk size is rounded up to
 *   MEM_PAGE_SIZE (4K), trying to have chunks in multiples of VM_PAGE size.
 *   Minimum Chunk size is MEM_CHUNK_SIZE (16K).
 *   A number of items fits into a single chunk, depending on item size.
 *   Maximum number of items per chunk is limited to MEM_MAX_FREE (65535).
 *
 *   We populate Chunk with a linkedlist, each node at first word of item,
 *   and pointing at next free item. Chunk->FreeList is pointing at first
 *   free node. Thus we stuff free housekeeping into the Chunk itself, and
 *   omit pointer overhead per item.
 *
 *   Chunks are created on demand, and new chunks are inserted into linklist
 *   of chunks so that Chunks with smaller pointer value are placed closer
 *   to the linklist head. Head is a hotspot, servicing most of requests, so
 *   slow sorting occurs and Chunks in highest memory tend to become idle
 *   and freeable.
 *
 *   event is registered that runs every 15 secs and checks reference time
 *   of each idle chunk. If a chunk is not referenced for 15 secs, it is
 *   released.
 *
 *   [If mem_idle_limit is exceeded with pools, every chunk that becomes
 *   idle is immediately considered for release, unless this is the only
 *   chunk with free items in it.] (not implemented)
 *
 *   In cachemgr output, there are new columns for chunking. Special item,
 *   Frag, is shown to estimate approximately fragmentation of chunked
 *   pools. Fragmentation is calculated by taking amount of items in use,
 *   calculating needed amount of chunks to fit all, and then comparing to
 *   actual amount of chunks in use. Frag number, in percent, is showing
 *   how many percent of chunks are in use excessively. 100% meaning that
 *   twice the needed amount of chunks are in use.
 *   "part" item shows number of chunks partially filled. This shows how
 *   badly fragmentation is spread across all chunks.
 *
 *   Andres Kroonmaa.
 *   Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "MemPool.h"
#include "MemPoolChunked.h"
#include "MemPoolMalloc.h"

#define FLUSH_LIMIT 1000	/* Flush memPool counters to memMeters after flush limit calls */
#define MEM_MAX_MMAP_CHUNKS 2048

#if HAVE_STRING_H
#include <string.h>
#endif

/*
 * XXX This is a boundary violation between lib and src.. would be good
 * if it could be solved otherwise, but left for now.
 */
extern time_t squid_curtime;

/* local data */
static MemPoolMeter TheMeter;
static MemPoolIterator Iterator;

static int Pool_id_counter = 0;

MemPools &
MemPools::GetInstance()
{
    /* Must use this idiom, as we can be double-initialised
     * if we are called during static initialisations.
     */
    if (!Instance)
        Instance = new MemPools;
    return *Instance;
}

MemPools * MemPools::Instance = NULL;

MemPoolIterator *
memPoolIterate(void)
{
    Iterator.pool = MemPools::GetInstance().pools;
    return &Iterator;
}

void
memPoolIterateDone(MemPoolIterator ** iter)
{
    assert(iter != NULL);
    Iterator.pool = NULL;
    *iter = NULL;
}

MemImplementingAllocator *
memPoolIterateNext(MemPoolIterator * iter)
{
    MemImplementingAllocator *pool;
    assert(iter != NULL);

    pool = iter->pool;
    if (!pool)
        return NULL;

    iter->pool = pool->next;
    return pool;
}

void
MemPools::setIdleLimit(size_t new_idle_limit)
{
    mem_idle_limit = new_idle_limit;
}

size_t
MemPools::idleLimit() const
{
    return mem_idle_limit;
}

/* Change the default calue of defaultIsChunked to override
 * all pools - including those used before main() starts where
 * MemPools::GetInstance().setDefaultPoolChunking() can be called.
 */
MemPools::MemPools() : pools(NULL), mem_idle_limit(2 * MB),
        poolCount (0), defaultIsChunked (USE_MEMPOOLS && !RUNNING_ON_VALGRIND)
{
    char *cfg = getenv("MEMPOOLS");
    if (cfg)
        defaultIsChunked = atoi(cfg);
#if HAVE_MALLOPT && M_MMAP_MAX
    mallopt(M_MMAP_MAX, MEM_MAX_MMAP_CHUNKS);
#endif
}

MemImplementingAllocator *
MemPools::create(const char *label, size_t obj_size)
{
    ++poolCount;
    if (defaultIsChunked)
        return new MemPoolChunked (label, obj_size);
    else
        return new MemPoolMalloc (label, obj_size);
}

void
MemPools::setDefaultPoolChunking(bool const &aBool)
{
    defaultIsChunked = aBool;
}

char const *
MemAllocator::objectType() const
{
    return label;
}

int
MemAllocator::inUseCount()
{
    return getInUseCount();
}

void
MemImplementingAllocator::flushMeters()
{
    size_t calls;

    calls = free_calls;
    if (calls) {
        meter.gb_freed.count += calls;
        free_calls = 0;
    }
    calls = alloc_calls;
    if (calls) {
        meter.gb_saved.count += calls;
        alloc_calls = 0;
    }
}

void
MemImplementingAllocator::flushMetersFull()
{
    flushMeters();
    getMeter().gb_saved.bytes = getMeter().gb_saved.count * obj_size;
    getMeter().gb_freed.bytes = getMeter().gb_freed.count * obj_size;
}

void
MemPoolMeter::flush()
{
    alloc.level = 0;
    inuse.level = 0;
    idle.level = 0;
    gb_saved.count = 0;
    gb_saved.bytes = 0;
    gb_freed.count = 0;
    gb_freed.bytes = 0;
}
/*
 * Updates all pool counters, and recreates TheMeter totals from all pools
 */
void
MemPools::flushMeters()
{
    MemImplementingAllocator *pool;
    MemPoolIterator *iter;

    TheMeter.flush();

    iter = memPoolIterate();
    while ((pool = memPoolIterateNext(iter))) {
        pool->flushMetersFull();
        memMeterAdd(TheMeter.alloc, pool->getMeter().alloc.level * pool->obj_size);
        memMeterAdd(TheMeter.inuse, pool->getMeter().inuse.level * pool->obj_size);
        memMeterAdd(TheMeter.idle, pool->getMeter().idle.level * pool->obj_size);
        TheMeter.gb_saved.count += pool->getMeter().gb_saved.count;
        TheMeter.gb_freed.count += pool->getMeter().gb_freed.count;
        TheMeter.gb_saved.bytes += pool->getMeter().gb_saved.bytes;
        TheMeter.gb_freed.bytes += pool->getMeter().gb_freed.bytes;
    }
    memPoolIterateDone(&iter);
}

void *
MemImplementingAllocator::alloc()
{
    if (++alloc_calls == FLUSH_LIMIT)
        flushMeters();

    return allocate();
}

void
MemImplementingAllocator::freeOne(void *obj)
{
    assert(obj != NULL);
    (void) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(obj, obj_size);
    deallocate(obj);
    ++free_calls;
}

/*
 * Returns all cached frees to their home chunks
 * If chunks unreferenced age is over, destroys Idle chunk
 * Flushes meters for a pool
 * If pool is not specified, iterates through all pools.
 * When used for all pools, if new_idle_limit is above -1, new
 * idle memory limit is set before Cleanup. This allows to shrink
 * memPool memory usage to specified minimum.
 */
void
MemPools::clean(time_t maxage)
{
    MemImplementingAllocator *pool;
    MemPoolIterator *iter;

    int shift = 1;
    flushMeters();
    if (TheMeter.idle.level > mem_idle_limit)
        maxage = shift = 0;

    iter = memPoolIterate();
    while ((pool = memPoolIterateNext(iter)))
        if (pool->idleTrigger(shift))
            pool->clean(maxage);
    memPoolIterateDone(&iter);
}

/* Persistent Pool stats. for GlobalStats accumulation */
static MemPoolStats pp_stats;

/*
 * Totals statistics is returned
 */
int
memPoolGetGlobalStats(MemPoolGlobalStats * stats)
{
    int pools_inuse = 0;
    MemAllocator *pool;
    MemPoolIterator *iter;

    memset(stats, 0, sizeof(MemPoolGlobalStats));
    memset(&pp_stats, 0, sizeof(MemPoolStats));

    MemPools::GetInstance().flushMeters(); /* recreate TheMeter */

    /* gather all stats for Totals */
    iter = memPoolIterate();
    while ((pool = memPoolIterateNext(iter))) {
        if (pool->getStats(&pp_stats, 1) > 0)
            pools_inuse++;
    }
    memPoolIterateDone(&iter);

    stats->TheMeter = &TheMeter;

    stats->tot_pools_alloc = MemPools::GetInstance().poolCount;
    stats->tot_pools_inuse = pools_inuse;
    stats->tot_pools_mempid = Pool_id_counter;

    stats->tot_chunks_alloc = pp_stats.chunks_alloc;
    stats->tot_chunks_inuse = pp_stats.chunks_inuse;
    stats->tot_chunks_partial = pp_stats.chunks_partial;
    stats->tot_chunks_free = pp_stats.chunks_free;
    stats->tot_items_alloc = pp_stats.items_alloc;
    stats->tot_items_inuse = pp_stats.items_inuse;
    stats->tot_items_idle = pp_stats.items_idle;

    stats->tot_overhead += pp_stats.overhead + MemPools::GetInstance().poolCount * sizeof(MemAllocator *);
    stats->mem_idle_limit = MemPools::GetInstance().mem_idle_limit;

    return pools_inuse;
}

MemAllocator::MemAllocator(char const *aLabel) : doZeroOnPush(true), label(aLabel)
{
}

size_t MemAllocator::RoundedSize(size_t s)
{
    return ((s + sizeof(void*) - 1) / sizeof(void*)) * sizeof(void*);
}

int
memPoolInUseCount(MemAllocator * pool)
{
    return pool->inUseCount();
}

int
memPoolsTotalAllocated(void)
{
    MemPoolGlobalStats stats;
    memPoolGetGlobalStats(&stats);
    return stats.TheMeter->alloc.level;
}

void *
MemAllocatorProxy::alloc()
{
    return getAllocator()->alloc();
}

void
MemAllocatorProxy::freeOne(void *address)
{
    getAllocator()->freeOne(address);
    /* TODO: check for empty, and if so, if the default type has altered,
     * switch
     */
}

MemAllocator *
MemAllocatorProxy::getAllocator() const
{
    if (!theAllocator)
        theAllocator = MemPools::GetInstance().create(objectType(), size);
    return theAllocator;
}

int
MemAllocatorProxy::inUseCount() const
{
    if (!theAllocator)
        return 0;
    else
        return memPoolInUseCount(theAllocator);
}

size_t
MemAllocatorProxy::objectSize() const
{
    return size;
}

char const *
MemAllocatorProxy::objectType() const
{
    return label;
}

MemPoolMeter const &
MemAllocatorProxy::getMeter() const
{
    return getAllocator()->getMeter();
}

int
MemAllocatorProxy::getStats(MemPoolStats * stats)
{
    return getAllocator()->getStats(stats);
}

MemImplementingAllocator::MemImplementingAllocator(char const *aLabel, size_t aSize) : MemAllocator(aLabel),
        next(NULL),
        alloc_calls(0),
        free_calls(0),
        obj_size(RoundedSize(aSize))
{
	memPID = ++Pool_id_counter;
}

void
MemAllocator::zeroOnPush(bool doIt)
{
    doZeroOnPush = doIt;
}

MemPoolMeter const &
MemImplementingAllocator::getMeter() const
{
    return meter;
}

MemPoolMeter &
MemImplementingAllocator::getMeter()
{
    return meter;
}

size_t
MemImplementingAllocator::objectSize() const
{
    return obj_size;
}
