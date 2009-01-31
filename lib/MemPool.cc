
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

/* local prototypes */
static int memCompChunks(MemChunk * const &, MemChunk * const &);
static int memCompObjChunks(void * const &, MemChunk * const &);

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

/* Compare chunks */
static int
memCompChunks(MemChunk * const &chunkA, MemChunk * const &chunkB)
{
    if (chunkA->objCache > chunkB->objCache)
        return 1;
    else if (chunkA->objCache < chunkB->objCache)
        return -1;
    else
        return 0;
}

/* Compare object to chunk */
static int
memCompObjChunks(void *const &obj, MemChunk * const &chunk)
{
    /* object is lower in memory than the chunks arena */
    if (obj < chunk->objCache)
        return -1;
    /* object is within the pool */
    if (obj < (void *) ((char *) chunk->objCache + chunk->pool->chunk_size))
        return 0;
    /* object is above the pool */
    return 1;
}

MemChunk::MemChunk(MemPool *aPool)
{
    /* should have a pool for this too -
     * note that this requres:
     * allocate one chunk for the pool of chunks's first chunk
     * allocate a chunk from that pool
     * move the contents of one chunk into the other
     * free the first chunk.
     */
    inuse_count = 0;
    next = NULL;
    pool = aPool;

    objCache = xcalloc(1, pool->chunk_size);
    freeList = objCache;
    void **Free = (void **)freeList;

    for (int i = 1; i < pool->chunk_capacity; i++) {
        *Free = (void *) ((char *) Free + pool->obj_size);
        void **nextFree = (void **)*Free;
        (void) VALGRIND_MAKE_MEM_NOACCESS(Free, pool->obj_size);
        Free = nextFree;
    }
    nextFreeChunk = pool->nextFreeChunk;
    pool->nextFreeChunk = this;

    memMeterAdd(pool->getMeter().alloc, pool->chunk_capacity);
    memMeterAdd(pool->getMeter().idle, pool->chunk_capacity);
    pool->idle += pool->chunk_capacity;
    pool->chunkCount++;
    lastref = squid_curtime;
    pool->allChunks.insert(this, memCompChunks);
}

MemPool::MemPool(const char *aLabel, size_t aSize) : MemImplementingAllocator(aLabel, aSize)
{
    chunk_size = 0;
    chunk_capacity = 0;
    memPID = 0;
    chunkCount = 0;
    inuse = 0;
    idle = 0;
    freeCache = 0;
    nextFreeChunk = 0;
    Chunks = 0;
    next = 0;
    MemImplementingAllocator *last_pool;

    assert(aLabel != NULL && aSize);

    setChunkSize(MEM_CHUNK_SIZE);

    /* Append as Last */
    for (last_pool = MemPools::GetInstance().pools; last_pool && last_pool->next;)
        last_pool = last_pool->next;
    if (last_pool)
        last_pool->next = this;
    else
        MemPools::GetInstance().pools = this;

    memPID = ++Pool_id_counter;
}

MemChunk::~MemChunk()
{
    memMeterDel(pool->getMeter().alloc, pool->chunk_capacity);
    memMeterDel(pool->getMeter().idle, pool->chunk_capacity);
    pool->idle -= pool->chunk_capacity;
    pool->chunkCount--;
    pool->allChunks.remove(this, memCompChunks);
    xfree(objCache);
}

void
MemPool::push(void *obj)
{
    void **Free;
    /* XXX We should figure out a sane way of avoiding having to clear
     * all buffers. For example data buffers such as used by MemBuf do
     * not really need to be cleared.. There was a condition based on
     * the object size here, but such condition is not safe.
     */
    if (doZeroOnPush)
        memset(obj, 0, obj_size);
    Free = (void **)obj;
    *Free = freeCache;
    freeCache = obj;
    (void) VALGRIND_MAKE_MEM_NOACCESS(obj, obj_size);
}

/*
 * Find a chunk with a free item.
 * Create new chunk on demand if no chunk with frees found.
 * Insert new chunk in front of lowest ram chunk, making it preferred in future,
 * and resulting slow compaction towards lowest ram area.
 */
void *
MemPool::get()
{
    void **Free;

    /* first, try cache */
    if (freeCache) {
        Free = (void **)freeCache;
        (void) VALGRIND_MAKE_MEM_DEFINED(Free, obj_size);
        freeCache = *Free;
        *Free = NULL;
        return Free;
    }
    /* then try perchunk freelist chain */
    if (nextFreeChunk == NULL) {
        /* no chunk with frees, so create new one */
        createChunk();
    }
    /* now we have some in perchunk freelist chain */
    MemChunk *chunk = nextFreeChunk;

    Free = (void **)chunk->freeList;
    chunk->freeList = *Free;
    *Free = NULL;
    chunk->inuse_count++;
    chunk->lastref = squid_curtime;

    if (chunk->freeList == NULL) {
        /* last free in this chunk, so remove us from perchunk freelist chain */
        nextFreeChunk = chunk->nextFreeChunk;
    }
    (void) VALGRIND_MAKE_MEM_DEFINED(Free, obj_size);
    return Free;
}

/* just create a new chunk and place it into a good spot in the chunk chain */
void
MemPool::createChunk()
{
    MemChunk *chunk, *newChunk;

    newChunk = new MemChunk(this);

    chunk = Chunks;
    if (chunk == NULL) {	/* first chunk in pool */
        Chunks = newChunk;
        return;
    }
    if (newChunk->objCache < chunk->objCache) {
        /* we are lowest ram chunk, insert as first chunk */
        newChunk->next = chunk;
        Chunks = newChunk;
        return;
    }
    while (chunk->next) {
        if (newChunk->objCache < chunk->next->objCache) {
            /* new chunk is in lower ram, insert here */
            newChunk->next = chunk->next;
            chunk->next = newChunk;
            return;
        }
        chunk = chunk->next;
    }
    /* we are the worst chunk in chain, add as last */
    chunk->next = newChunk;
}

/* Change the default calue of defaultIsChunked to override
 * all pools - including those used before main() starts where
 * MemPools::GetInstance().setDefaultPoolChunking() can be called.
 */
MemPools::MemPools() : pools(NULL), mem_idle_limit(2 * MB),
        poolCount (0), defaultIsChunked (!DISABLE_POOLS && !RUNNING_ON_VALGRIND)
{
    char *cfg = getenv("MEMPOOLS");
    if (cfg)
        defaultIsChunked = atoi(cfg);
#if HAVE_MALLOPT && M_MMAP_MAX
    mallopt(M_MMAP_MAX, MEM_MAX_MMAP_CHUNKS);
#endif
}

void
MemPool::setChunkSize(size_t chunksize)
{
    int cap;
    size_t csize = chunksize;

    if (Chunks)		/* unsafe to tamper */
        return;

    csize = ((csize + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE) * MEM_PAGE_SIZE;	/* round up to page size */
    cap = csize / obj_size;

    if (cap < MEM_MIN_FREE)
        cap = MEM_MIN_FREE;
    if (cap * obj_size > MEM_CHUNK_MAX_SIZE)
        cap = MEM_CHUNK_MAX_SIZE / obj_size;
    if (cap > MEM_MAX_FREE)
        cap = MEM_MAX_FREE;
    if (cap < 1)
        cap = 1;

    csize = cap * obj_size;
    csize = ((csize + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE) * MEM_PAGE_SIZE;	/* round up to page size */
    cap = csize / obj_size;

    chunk_capacity = cap;
    chunk_size = csize;
}

MemImplementingAllocator *
MemPools::create(const char *label, size_t obj_size)
{
    return create (label, obj_size, defaultIsChunked);
}

MemImplementingAllocator *
MemPools::create(const char *label, size_t obj_size, bool const chunked)
{
    ++poolCount;
    if (chunked)
        return new MemPool (label, obj_size);
    else
        return new MemMalloc (label, obj_size);
}

void
MemPools::setDefaultPoolChunking(bool const &aBool)
{
    defaultIsChunked = aBool;
}

/*
 * warning: we do not clean this entry from Pools assuming destruction
 * is used at the end of the program only
 */
MemPool::~MemPool()
{
    MemChunk *chunk, *fchunk;
    MemImplementingAllocator *find_pool, *prev_pool;

    flushMetersFull();
    clean(0);
    assert(inuse == 0 && "While trying to destroy pool");

    chunk = Chunks;
    while ( (fchunk = chunk) != NULL) {
        chunk = chunk->next;
        delete fchunk;
    }
    /* TODO we should be doing something about the original Chunks pointer here. */

    assert(MemPools::GetInstance().pools != NULL && "Called MemPool::~MemPool, but no pool exists!");

    /* Pool clean, remove it from List and free */
    for (find_pool = MemPools::GetInstance().pools, prev_pool = NULL; (find_pool && this != find_pool); find_pool = find_pool->next)
        prev_pool = find_pool;
    assert(find_pool != NULL && "pool to destroy not found");

    if (prev_pool)
        prev_pool->next = next;
    else
        MemPools::GetInstance().pools = next;
    --MemPools::GetInstance().poolCount;
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
        getMeter().gb_freed.count += calls;
        memMeterDel(getMeter().inuse, calls);
        memMeterAdd(getMeter().idle, calls);
        free_calls = 0;
    }
    calls = alloc_calls;
    if (calls) {
        meter.gb_saved.count += calls;
        memMeterAdd(meter.inuse, calls);
        memMeterDel(meter.idle, calls);
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
MemMalloc::allocate()
{
    inuse++;
    return xcalloc(1, obj_size);
}

void
MemMalloc::deallocate(void *obj)
{
    inuse--;
    xfree(obj);
}

void *
MemImplementingAllocator::alloc()
{
    if (++alloc_calls == FLUSH_LIMIT)
        flushMeters();

    return allocate();
}

void
MemImplementingAllocator::free(void *obj)
{
    assert(obj != NULL);
    (void) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(obj, obj_size);
    deallocate(obj);
    ++free_calls;
}

int
MemPool::getInUseCount()
{
    return inuse;
}

void *
MemPool::allocate()
{
    void *p = get();
    assert(idle);
    --idle;
    ++inuse;
    return p;
}

void
MemPool::deallocate(void *obj)
{
    push(obj);
    assert(inuse);
    --inuse;
    ++idle;
}

void
MemPool::convertFreeCacheToChunkFreeCache()
{
    void *Free;
    /*
     * OK, so we have to go through all the global freeCache and find the Chunk
     * any given Free belongs to, and stuff it into that Chunk's freelist
     */

    while ((Free = freeCache) != NULL) {
        MemChunk *chunk = NULL;
        chunk = const_cast<MemChunk *>(*allChunks.find(Free, memCompObjChunks));
        assert(splayLastResult == 0);
        assert(chunk->inuse_count > 0);
        chunk->inuse_count--;
        (void) VALGRIND_MAKE_MEM_DEFINED(Free, sizeof(void *));
        freeCache = *(void **)Free;	/* remove from global cache */
        *(void **)Free = chunk->freeList;	/* stuff into chunks freelist */
        (void) VALGRIND_MAKE_MEM_NOACCESS(Free, sizeof(void *));
        chunk->freeList = Free;
        chunk->lastref = squid_curtime;
    }

}

/* removes empty Chunks from pool */
void
MemPool::clean(time_t maxage)
{
    MemChunk *chunk, *freechunk, *listTail;
    time_t age;

    if (!this)
        return;
    if (!Chunks)
        return;

    flushMetersFull();
    convertFreeCacheToChunkFreeCache();
    /* Now we have all chunks in this pool cleared up, all free items returned to their home */
    /* We start now checking all chunks to see if we can release any */
    /* We start from Chunks->next, so first chunk is not released */
    /* Recreate nextFreeChunk list from scratch */

    chunk = Chunks;
    while ((freechunk = chunk->next) != NULL) {
        age = squid_curtime - freechunk->lastref;
        freechunk->nextFreeChunk = NULL;
        if (freechunk->inuse_count == 0)
            if (age >= maxage) {
                chunk->next = freechunk->next;
                delete freechunk;
                freechunk = NULL;
            }
        if (chunk->next == NULL)
            break;
        chunk = chunk->next;
    }

    /* Recreate nextFreeChunk list from scratch */
    /* Populate nextFreeChunk list in order of "most filled chunk first" */
    /* in case of equal fill, put chunk in lower ram first */
    /* First (create time) chunk is always on top, no matter how full */

    chunk = Chunks;
    nextFreeChunk = chunk;
    chunk->nextFreeChunk = NULL;

    while (chunk->next) {
        chunk->next->nextFreeChunk = NULL;
        if (chunk->next->inuse_count < chunk_capacity) {
            listTail = nextFreeChunk;
            while (listTail->nextFreeChunk) {
                if (chunk->next->inuse_count > listTail->nextFreeChunk->inuse_count)
                    break;
                if ((chunk->next->inuse_count == listTail->nextFreeChunk->inuse_count) &&
                        (chunk->next->objCache < listTail->nextFreeChunk->objCache))
                    break;
                listTail = listTail->nextFreeChunk;
            }
            chunk->next->nextFreeChunk = listTail->nextFreeChunk;
            listTail->nextFreeChunk = chunk->next;
        }
        chunk = chunk->next;
    }
    /* We started from 2nd chunk. If first chunk is full, remove it */
    if (nextFreeChunk->inuse_count == chunk_capacity)
        nextFreeChunk = nextFreeChunk->nextFreeChunk;

    return;
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

bool
MemPool::idleTrigger(int shift) const
{
    return getMeter().idle.level > (chunk_capacity << shift);
}

/* Persistent Pool stats. for GlobalStats accumulation */
static MemPoolStats pp_stats;

/*
 * Update MemPoolStats struct for single pool
 */
int
MemPool::getStats(MemPoolStats * stats)
{
    MemChunk *chunk;
    int chunks_free = 0;
    int chunks_partial = 0;

    if (stats != &pp_stats)	/* need skip memset for GlobalStats accumulation */
        /* XXX Fixme */
        memset(stats, 0, sizeof(MemPoolStats));

    clean((time_t) 555555);	/* don't want to get chunks released before reporting */

    stats->pool = this;
    stats->label = objectType();
    stats->meter = &getMeter();
    stats->obj_size = obj_size;
    stats->chunk_capacity = chunk_capacity;

    /* gather stats for each Chunk */
    chunk = Chunks;
    while (chunk) {
        if (chunk->inuse_count == 0)
            chunks_free++;
        else if (chunk->inuse_count < chunk_capacity)
            chunks_partial++;
        chunk = chunk->next;
    }

    stats->chunks_alloc += chunkCount;
    stats->chunks_inuse += chunkCount - chunks_free;
    stats->chunks_partial += chunks_partial;
    stats->chunks_free += chunks_free;

    stats->items_alloc += getMeter().alloc.level;
    stats->items_inuse += getMeter().inuse.level;
    stats->items_idle += getMeter().idle.level;

    stats->overhead += sizeof(MemPool) + chunkCount * sizeof(MemChunk) + strlen(objectType()) + 1;

    return getMeter().inuse.level;
}

/* TODO extract common logic to MemAllocate */
int
MemMalloc::getStats(MemPoolStats * stats)
{
    if (stats != &pp_stats)	/* need skip memset for GlobalStats accumulation */
        /* XXX Fixme */
        memset(stats, 0, sizeof(MemPoolStats));

    stats->pool = this;
    stats->label = objectType();
    stats->meter = &getMeter();
    stats->obj_size = obj_size;
    stats->chunk_capacity = 0;

    stats->chunks_alloc += 0;
    stats->chunks_inuse += 0;
    stats->chunks_partial += 0;
    stats->chunks_free += 0;

    stats->items_alloc += getMeter().alloc.level;
    stats->items_inuse += getMeter().inuse.level;
    stats->items_idle += getMeter().idle.level;

    stats->overhead += sizeof(MemMalloc) + strlen(objectType()) + 1;

    return getMeter().inuse.level;
}

int
MemMalloc::getInUseCount()
{
    return inuse;
}

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
        if (pool->getStats(&pp_stats) > 0)
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

    stats->tot_overhead += pp_stats.overhead + MemPools::GetInstance().poolCount * sizeof(MemPool *);
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

MemMalloc::MemMalloc(char const *label, size_t aSize) : MemImplementingAllocator(label, aSize) { inuse = 0; }

bool
MemMalloc::idleTrigger(int shift) const
{
    return false;
}

void
MemMalloc::clean(time_t maxage)
{
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
MemAllocatorProxy::free(void *address)
{
    getAllocator()->free(address);
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
