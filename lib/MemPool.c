
/*
 * $Id: MemPool.c,v 1.11 2002/04/16 00:33:29 hno Exp $
 *
 * DEBUG: section 63    Low Level Memory Pool Management
 * AUTHOR: Alex Rousskov, Andres Kroonmaa
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
 */

#define FLUSH_LIMIT 1000	/* Flush memPool counters to memMeters after flush limit calls */
#define MEM_MAX_MMAP_CHUNKS 2048

#include <assert.h>

#include "config.h"
#if HAVE_STRING_H
#include <string.h>
#endif
#include "MemPool.h"

/*
 * XXX This is a boundary violation between lib and src.. would be good
 * if it could be solved otherwise, but left for now.
 */
extern time_t squid_curtime;

/* Allocator API */
extern MemPool *memPoolCreate(const char *label, size_t obj_size);
extern void *memPoolAlloc(MemPool * pool);
extern void memPoolFree(MemPool * pool, void *obj);
extern void memPoolDestroy(MemPool ** pool);

extern MemPoolIterator *memPoolIterate(void);
extern MemPool *memPoolIterateNext(MemPoolIterator * iter);
extern void memPoolIterateDone(MemPoolIterator ** iter);

/* Tune API */
extern void memPoolSetChunkSize(MemPool * pool, size_t chunksize);
extern void memPoolSetIdleLimit(size_t new_idle_limit);

/* Stats API */
extern int memPoolGetStats(MemPoolStats * stats, MemPool * pool);
extern int memPoolGetGlobalStats(MemPoolGlobalStats * stats);

/* Module housekeeping API */
extern void memPoolClean(time_t maxage);

/* local data */
static int mempool_initialised = 0;
static int mem_idle_limit = 0;
static MemPool *memPools = NULL;
static int memPools_alloc = 0;

static MemPoolMeter TheMeter;
static MemPoolIterator Iterator;

static int Pool_id_counter = 0;
static MemPool *lastPool;

/* local prototypes */
static int memCompChunks(MemChunk * chunkA, MemChunk * chunkB);
static int memCompObjChunks(void *obj, MemChunk * chunk);
static MemChunk *memPoolChunkNew(MemPool * pool);
static void memPoolChunkDestroy(MemPool * pool, MemChunk * chunk);
static void memPoolPush(MemPool * pool, void *obj);
static void *memPoolGet(MemPool * pool);
static void memPoolCreateChunk(MemPool * pool);
static void memPoolFlushMeters(MemPool * pool);
static void memPoolFlushMetersFull(MemPool * pool);
static void memPoolFlushMetersAll(void);
static void memPoolCleanOne(MemPool * pool, time_t maxage);

static void memPoolInit(void);

MemPoolIterator *
memPoolIterate(void)
{
    Iterator.pool = memPools;
    return &Iterator;
}

void
memPoolIterateDone(MemPoolIterator ** iter)
{
    assert(iter);
    Iterator.pool = NULL;
    *iter = NULL;
}

MemPool *
memPoolIterateNext(MemPoolIterator * iter)
{
    MemPool *pool;
    assert(iter);

    pool = iter->pool;
    if (!pool)
	return NULL;

    iter->pool = pool->next;
    return pool;
}

void
memPoolSetIdleLimit(size_t new_idle_limit)
{
    mem_idle_limit = new_idle_limit;
}

/* Compare chunks */
static int
memCompChunks(MemChunk * chunkA, MemChunk * chunkB)
{
    if (chunkA->objCache > chunkB->objCache)
	return 1;
    else if (chunkA->objCache < chunkB->objCache)
	return -1;
    else
	return 0;
}

/* Compare object to chunk */
/* XXX Note: this depends on lastPool */
static int
memCompObjChunks(void *obj, MemChunk * chunk)
{
    if (obj < chunk->objCache)
	return -1;
    if (obj < (void *)((char *)chunk->objCache + lastPool->chunk_size))
	return 0;
    return 1;
}

static MemChunk *
memPoolChunkNew(MemPool * pool)
{
    int i;
    void **Free;
    MemChunk *chunk;

    chunk = xcalloc(1, sizeof(MemChunk));	/* should have a pool for this too */
    chunk->objCache = xcalloc(1, pool->chunk_size);
    Free = chunk->freeList = chunk->objCache;

    for (i = 1; i < pool->chunk_capacity; i++) {
	*Free = (void *) ((char *)Free + pool->obj_size);
	Free = *Free;
    }
    chunk->nextFreeChunk = pool->nextFreeChunk;
    pool->nextFreeChunk = chunk;

    memMeterAdd(pool->meter.alloc, pool->chunk_capacity);
    memMeterAdd(pool->meter.idle, pool->chunk_capacity);
    pool->idle += pool->chunk_capacity;
    pool->chunkCount++;
    chunk->lastref = squid_curtime;
    lastPool = pool;
    pool->allChunks = splay_insert(chunk, pool->allChunks, (SPLAYCMP *) memCompChunks);
    return chunk;
}

static void
memPoolChunkDestroy(MemPool * pool, MemChunk * chunk)
{
    memMeterDel(pool->meter.alloc, pool->chunk_capacity);
    memMeterDel(pool->meter.idle, pool->chunk_capacity);
    pool->idle -= pool->chunk_capacity;
    pool->chunkCount--;
    lastPool = pool;
    pool->allChunks = splay_delete(chunk, pool->allChunks, (SPLAYCMP *) memCompChunks);
    xfree(chunk->objCache);
    xfree(chunk);
}

static void
memPoolPush(MemPool * pool, void *obj)
{
    void **Free;
    /* XXX We should figure out a sane way of avoiding having to clear
     * all buffers. For example data buffers such as used by MemBuf do
     * not really need to be cleared.. There was a condition based on
     * the object size here, but such condition is not safe.
     */
	memset(obj, 0, pool->obj_size);
    Free = obj;
    *Free = pool->freeCache;
    pool->freeCache = obj;
    return;
}

/*
 * Find a chunk with a free item.
 * Create new chunk on demand if no chunk with frees found.
 * Insert new chunk in front of lowest ram chunk, making it preferred in future,
 * and resulting slow compaction towards lowest ram area.
 */
static void *
memPoolGet(MemPool * pool)
{
    MemChunk *chunk;
    void **Free;

    /* first, try cache */
    if (pool->freeCache) {
	Free = pool->freeCache;
	pool->freeCache = *Free;
	*Free = NULL;
	return Free;
    }
    /* then try perchunk freelist chain */
    if (pool->nextFreeChunk == NULL) {
	/* no chunk with frees, so create new one */
	memPoolCreateChunk(pool);
    }
    /* now we have some in perchunk freelist chain */
    chunk = pool->nextFreeChunk;

    Free = chunk->freeList;
    chunk->freeList = *Free;
    *Free = NULL;
    chunk->inuse_count++;
    chunk->lastref = squid_curtime;

    if (chunk->freeList == NULL) {
	/* last free in this chunk, so remove us from perchunk freelist chain */
	pool->nextFreeChunk = chunk->nextFreeChunk;
    }
    return Free;
}

/* just create a new chunk and place it into a good spot in the chunk chain */
static void
memPoolCreateChunk(MemPool * pool)
{
    MemChunk *chunk, *new;

    new = memPoolChunkNew(pool);

    chunk = pool->Chunks;
    if (chunk == NULL) {	/* first chunk in pool */
	pool->Chunks = new;
	return;
    }
    if (new->objCache < chunk->objCache) {
	/* we are lowest ram chunk, insert as first chunk */
	new->next = chunk;
	pool->Chunks = new;
	return;
    }
    while (chunk->next) {
	if (new->objCache < chunk->next->objCache) {
	    /* new chunk is in lower ram, insert here */
	    new->next = chunk->next;
	    chunk->next = new;
	    return;
	}
	chunk = chunk->next;
    }
    /* we are the worst chunk in chain, add as last */
    chunk->next = new;
    return;
}

static void
memPoolInit(void)
{
    memPools = NULL;
    memPools_alloc = 0;
    memset(&TheMeter, 0, sizeof(TheMeter));
    mem_idle_limit = 2 * MB;
    mempool_initialised = 1;
#if HAVE_MALLOPT && M_MMAP_MAX
    mallopt(M_MMAP_MAX, MEM_MAX_MMAP_CHUNKS);
#endif
}

void
memPoolSetChunkSize(MemPool * pool, size_t chunksize)
{
    int cap;
    size_t csize = chunksize;

    if (pool->Chunks)		/* unsafe to tamper */
	return;

    csize = ((csize + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE) * MEM_PAGE_SIZE;	/* round up to page size */
    cap = csize / pool->obj_size;

    if (cap < MEM_MIN_FREE)
	cap = MEM_MIN_FREE;
    if (cap * pool->obj_size > MEM_CHUNK_MAX_SIZE)
	cap = MEM_CHUNK_MAX_SIZE / pool->obj_size;
    if (cap > MEM_MAX_FREE)
	cap = MEM_MAX_FREE;
    if (cap < 1)
	cap = 1;

    csize = cap * pool->obj_size;
    csize = ((csize + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE) * MEM_PAGE_SIZE;	/* round up to page size */
    cap = csize / pool->obj_size;

    pool->chunk_capacity = cap;
    pool->chunk_size = csize;
}

MemPool *
memPoolCreate(const char *label, size_t obj_size)
{
    MemPool *pool, *last_pool;

    if (!mempool_initialised)
	memPoolInit();

    pool = xcalloc(1, sizeof(MemPool));
    assert(label && obj_size);
    pool->label = label;
    pool->obj_size = obj_size;
    pool->obj_size =
	((obj_size + sizeof(void *) - 1) / sizeof(void *)) * sizeof(void *);

    memPoolSetChunkSize(pool, MEM_CHUNK_SIZE);

    /* Append as Last */
    for (last_pool = memPools; last_pool && last_pool->next;)
	last_pool = last_pool->next;
    if (last_pool)
	last_pool->next = pool;
    else
	memPools = pool;

    memPools_alloc++;
    pool->memPID = ++Pool_id_counter;
    return pool;
}

/*
 * warning: we do not clean this entry from Pools assuming memPoolDestroy
 * is used at the end of the program only
 */
void
memPoolDestroy(MemPool ** pool)
{
    MemChunk *chunk, *fchunk;
    MemPool *find_pool, *free_pool, *prev_pool;

    assert(pool);
    assert(*pool);
    free_pool = *pool;
    memPoolFlushMetersFull(free_pool);
    memPoolCleanOne(free_pool, 0);
    assert(free_pool->inuse == 0 && "While trying to destroy pool");

    for (chunk = free_pool->Chunks; (fchunk = chunk) != NULL; chunk = chunk->next)
	memPoolChunkDestroy(free_pool, fchunk);

    assert(memPools && "Called memPoolDestroy, but no pool exists!");

    /* Pool clean, remove it from List and free */
    for (find_pool = memPools, prev_pool = NULL; (find_pool && free_pool != find_pool); find_pool = find_pool->next)
	prev_pool = find_pool;
    assert(find_pool && "pool to destroy not found");

    if (prev_pool)
	prev_pool->next = free_pool->next;
    else
	memPools = free_pool->next;
    xfree(free_pool);
    memPools_alloc--;
    *pool = NULL;
}

static void
memPoolFlushMeters(MemPool * pool)
{
    size_t calls;

    calls = pool->free_calls;
    if (calls) {
	pool->meter.gb_freed.count += calls;
	memMeterDel(pool->meter.inuse, calls);
#if !DISABLE_POOLS
	memMeterAdd(pool->meter.idle, calls);
#endif
	pool->free_calls = 0;
    }
    calls = pool->alloc_calls;
    if (calls) {
	pool->meter.gb_saved.count += calls;
	memMeterAdd(pool->meter.inuse, calls);
#if !DISABLE_POOLS
	memMeterDel(pool->meter.idle, calls);
#endif
	pool->alloc_calls = 0;
    }
}

static void
memPoolFlushMetersFull(MemPool * pool)
{
    memPoolFlushMeters(pool);
    pool->meter.gb_saved.bytes = pool->meter.gb_saved.count * pool->obj_size;
    pool->meter.gb_freed.bytes = pool->meter.gb_freed.count * pool->obj_size;
}

/*
 * Updates all pool counters, and recreates TheMeter totals from all pools
 */
static void
memPoolFlushMetersAll(void)
{
    MemPool *pool;
    MemPoolIterator *iter;

    TheMeter.alloc.level = 0;
    TheMeter.inuse.level = 0;
    TheMeter.idle.level = 0;
    TheMeter.gb_saved.count = 0;
    TheMeter.gb_saved.bytes = 0;
    TheMeter.gb_freed.count = 0;
    TheMeter.gb_freed.bytes = 0;

    iter = memPoolIterate();
    while ((pool = memPoolIterateNext(iter))) {
	memPoolFlushMetersFull(pool);
	memMeterAdd(TheMeter.alloc, pool->meter.alloc.level * pool->obj_size);
	memMeterAdd(TheMeter.inuse, pool->meter.inuse.level * pool->obj_size);
	memMeterAdd(TheMeter.idle, pool->meter.idle.level * pool->obj_size);
	TheMeter.gb_saved.count += pool->meter.gb_saved.count;
	TheMeter.gb_freed.count += pool->meter.gb_freed.count;
	TheMeter.gb_saved.bytes += pool->meter.gb_saved.bytes;
	TheMeter.gb_freed.bytes += pool->meter.gb_freed.bytes;
    }
    memPoolIterateDone(&iter);
}

void *
memPoolAlloc(MemPool * pool)
{
    void *p;
    assert(pool);
#if !DISABLE_POOLS
    p = memPoolGet(pool);
    assert(pool->idle);
    pool->idle--;
    pool->inuse++;
#else
    p = xcalloc(1, pool->obj_size);
#endif
    if (++pool->alloc_calls == FLUSH_LIMIT)
	memPoolFlushMeters(pool);

    return p;
}

void
memPoolFree(MemPool * pool, void *obj)
{
    assert(pool && obj);
#if !DISABLE_POOLS

    memPoolPush(pool, obj);
    assert(pool->inuse);
    pool->inuse--;
    pool->idle++;
#else
    xfree(obj);
#endif
    ++pool->free_calls;

}

/* removes empty Chunks from pool */
static void
memPoolCleanOne(MemPool * pool, time_t maxage)
{
    MemChunk *chunk, *freechunk, *listTail;
    void **Free;
    time_t age;

    if (!pool)
	return;
    if (!pool->Chunks)
	return;

    memPoolFlushMetersFull(pool);
    /*
     * OK, so we have to go through all the global freeCache and find the Chunk
     * any given Free belongs to, and stuff it into that Chunk's freelist 
     */

    while ((Free = pool->freeCache) != NULL) {
	lastPool = pool;
	pool->allChunks = splay_splay(Free, pool->allChunks, (SPLAYCMP *) memCompObjChunks);
	assert(splayLastResult == 0);
	chunk = pool->allChunks->data;
	assert(chunk->inuse_count > 0);
	chunk->inuse_count--;
	pool->freeCache = *Free;	/* remove from global cache */
	*Free = chunk->freeList;	/* stuff into chunks freelist */
	chunk->freeList = Free;
	chunk->lastref = squid_curtime;
    }

    /* Now we have all chunks in this pool cleared up, all free items returned to their home */
    /* We start now checking all chunks to see if we can release any */
    /* We start from pool->Chunks->next, so first chunk is not released */
    /* Recreate nextFreeChunk list from scratch */

    chunk = pool->Chunks;
    while ((freechunk = chunk->next) != NULL) {
	age = squid_curtime - freechunk->lastref;
	freechunk->nextFreeChunk = NULL;
	if (freechunk->inuse_count == 0)
	    if (age >= maxage) {
		chunk->next = freechunk->next;
		memPoolChunkDestroy(pool, freechunk);
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

    chunk = pool->Chunks;
    pool->nextFreeChunk = chunk;
    chunk->nextFreeChunk = NULL;

    while (chunk->next) {
	chunk->next->nextFreeChunk = NULL;
	if (chunk->next->inuse_count < pool->chunk_capacity) {
	    listTail = pool->nextFreeChunk;
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
    if (pool->nextFreeChunk->inuse_count == pool->chunk_capacity)
	pool->nextFreeChunk = pool->nextFreeChunk->nextFreeChunk;

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
memPoolClean(time_t maxage)
{
    MemPool *pool;
    MemPoolIterator *iter;

    int shift = 1;
    memPoolFlushMetersAll();
    if (TheMeter.idle.level > mem_idle_limit)
	maxage = shift = 0;

    iter = memPoolIterate();
    while ((pool = memPoolIterateNext(iter))) {
	if (pool->meter.idle.level > (pool->chunk_capacity << shift)) {
	    memPoolCleanOne(pool, maxage);
	}
    }
    memPoolIterateDone(&iter);
}

/* Persistent Pool stats. for GlobalStats accumulation */
static MemPoolStats pp_stats;

/*
 * Update MemPoolStats struct for single pool
 */
int
memPoolGetStats(MemPoolStats * stats, MemPool * pool)
{
    MemChunk *chunk;
    int chunks_free = 0;
    int chunks_partial = 0;

    if (stats != &pp_stats)	/* need skip memset for GlobalStats accumulation */
	memset(stats, 0, sizeof(MemPoolStats));

    memPoolCleanOne(pool, (time_t) 555555);	/* don't want to get chunks released before reporting */

    stats->pool = pool;
    stats->label = pool->label;
    stats->meter = &pool->meter;
    stats->obj_size = pool->obj_size;
    stats->chunk_capacity = pool->chunk_capacity;

    /* gather stats for each Chunk */
    chunk = pool->Chunks;
    while (chunk) {
	if (chunk->inuse_count == 0)
	    chunks_free++;
	else if (chunk->inuse_count < pool->chunk_capacity)
	    chunks_partial++;
	chunk = chunk->next;
    }

    stats->chunks_alloc += pool->chunkCount;
    stats->chunks_inuse += pool->chunkCount - chunks_free;
    stats->chunks_partial += chunks_partial;
    stats->chunks_free += chunks_free;

    stats->items_alloc += pool->meter.alloc.level;
    stats->items_inuse += pool->meter.inuse.level;
    stats->items_idle += pool->meter.idle.level;

    stats->overhead += sizeof(MemPool) + pool->chunkCount * sizeof(MemChunk) + strlen(pool->label) + 1;

    return pool->meter.inuse.level;
}

/*
 * Totals statistics is returned
 */
int
memPoolGetGlobalStats(MemPoolGlobalStats * stats)
{
    int pools_inuse = 0;
    MemPool *pool;
    MemPoolIterator *iter;

    memset(stats, 0, sizeof(MemPoolGlobalStats));
    memset(&pp_stats, 0, sizeof(MemPoolStats));

    memPoolFlushMetersAll();	/* recreate TheMeter */

    /* gather all stats for Totals */
    iter = memPoolIterate();
    while ((pool = memPoolIterateNext(iter))) {
	if (memPoolGetStats(&pp_stats, pool) > 0)
	    pools_inuse++;
    }
    memPoolIterateDone(&iter);

    stats->TheMeter = &TheMeter;

    stats->tot_pools_alloc = memPools_alloc;
    stats->tot_pools_inuse = pools_inuse;
    stats->tot_pools_mempid = Pool_id_counter;

    stats->tot_chunks_alloc = pp_stats.chunks_alloc;
    stats->tot_chunks_inuse = pp_stats.chunks_inuse;
    stats->tot_chunks_partial = pp_stats.chunks_partial;
    stats->tot_chunks_free = pp_stats.chunks_free;
    stats->tot_items_alloc = pp_stats.items_alloc;
    stats->tot_items_inuse = pp_stats.items_inuse;
    stats->tot_items_idle = pp_stats.items_idle;

    stats->tot_overhead += pp_stats.overhead + memPools_alloc * sizeof(MemPool *);
    stats->mem_idle_limit = mem_idle_limit;

    return pools_inuse;
}
