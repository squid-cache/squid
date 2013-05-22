
/*
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

#include "squid.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "MemPoolChunked.h"

#define MEM_MAX_MMAP_CHUNKS 2048

#if HAVE_STRING_H
#include <string.h>
#endif

/*
 * XXX This is a boundary violation between lib and src.. would be good
 * if it could be solved otherwise, but left for now.
 */
extern time_t squid_curtime;

/* local prototypes */
static int memCompChunks(MemChunk * const &, MemChunk * const &);
static int memCompObjChunks(void * const &, MemChunk * const &);

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

MemChunk::MemChunk(MemPoolChunked *aPool)
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

    if (pool->doZero)
        objCache = xcalloc(1, pool->chunk_size);
    else
        objCache = xmalloc(pool->chunk_size);

    freeList = objCache;
    void **Free = (void **)freeList;

    for (int i = 1; i < pool->chunk_capacity; ++i) {
        *Free = (void *) ((char *) Free + pool->obj_size);
        void **nextFree = (void **)*Free;
        (void) VALGRIND_MAKE_MEM_NOACCESS(Free, pool->obj_size);
        Free = nextFree;
    }
    nextFreeChunk = pool->nextFreeChunk;
    pool->nextFreeChunk = this;

    memMeterAdd(pool->getMeter().alloc, pool->chunk_capacity);
    memMeterAdd(pool->getMeter().idle, pool->chunk_capacity);
    ++pool->chunkCount;
    lastref = squid_curtime;
    pool->allChunks.insert(this, memCompChunks);
}

MemPoolChunked::MemPoolChunked(const char *aLabel, size_t aSize) : MemImplementingAllocator(aLabel, aSize)
{
    chunk_size = 0;
    chunk_capacity = 0;
    chunkCount = 0;
    freeCache = 0;
    nextFreeChunk = 0;
    Chunks = 0;
    next = 0;

    setChunkSize(MEM_CHUNK_SIZE);

#if HAVE_MALLOPT && M_MMAP_MAX
    mallopt(M_MMAP_MAX, MEM_MAX_MMAP_CHUNKS);
#endif
}

MemChunk::~MemChunk()
{
    memMeterDel(pool->getMeter().alloc, pool->chunk_capacity);
    memMeterDel(pool->getMeter().idle, pool->chunk_capacity);
    -- pool->chunkCount;
    pool->allChunks.remove(this, memCompChunks);
    xfree(objCache);
}

void
MemPoolChunked::push(void *obj)
{
    void **Free;
    /* XXX We should figure out a sane way of avoiding having to clear
     * all buffers. For example data buffers such as used by MemBuf do
     * not really need to be cleared.. There was a condition based on
     * the object size here, but such condition is not safe.
     */
    if (doZero)
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
MemPoolChunked::get()
{
    void **Free;

    ++saved_calls;

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
        -- saved_calls; // compensate for the ++ above
        createChunk();
    }
    /* now we have some in perchunk freelist chain */
    MemChunk *chunk = nextFreeChunk;

    Free = (void **)chunk->freeList;
    chunk->freeList = *Free;
    *Free = NULL;
    ++chunk->inuse_count;
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
MemPoolChunked::createChunk()
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

void
MemPoolChunked::setChunkSize(size_t chunksize)
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

/*
 * warning: we do not clean this entry from Pools assuming destruction
 * is used at the end of the program only
 */
MemPoolChunked::~MemPoolChunked()
{
    MemChunk *chunk, *fchunk;

    flushMetersFull();
    clean(0);
    assert(meter.inuse.level == 0);

    chunk = Chunks;
    while ( (fchunk = chunk) != NULL) {
        chunk = chunk->next;
        delete fchunk;
    }
    /* TODO we should be doing something about the original Chunks pointer here. */

}

int
MemPoolChunked::getInUseCount()
{
    return meter.inuse.level;
}

void *
MemPoolChunked::allocate()
{
    void *p = get();
    assert(meter.idle.level > 0);
    memMeterDec(meter.idle);
    memMeterInc(meter.inuse);
    return p;
}

void
MemPoolChunked::deallocate(void *obj, bool aggressive)
{
    push(obj);
    assert(meter.inuse.level > 0);
    memMeterDec(meter.inuse);
    memMeterInc(meter.idle);
}

void
MemPoolChunked::convertFreeCacheToChunkFreeCache()
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
        -- chunk->inuse_count;
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
MemPoolChunked::clean(time_t maxage)
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

bool
MemPoolChunked::idleTrigger(int shift) const
{
    return meter.idle.level > (chunk_capacity << shift);
}

/*
 * Update MemPoolStats struct for single pool
 */
int
MemPoolChunked::getStats(MemPoolStats * stats, int accumulate)
{
    MemChunk *chunk;
    int chunks_free = 0;
    int chunks_partial = 0;

    if (!accumulate)	/* need skip memset for GlobalStats accumulation */
        memset(stats, 0, sizeof(MemPoolStats));

    clean((time_t) 555555);	/* don't want to get chunks released before reporting */

    stats->pool = this;
    stats->label = objectType();
    stats->meter = &meter;
    stats->obj_size = obj_size;
    stats->chunk_capacity = chunk_capacity;

    /* gather stats for each Chunk */
    chunk = Chunks;
    while (chunk) {
        if (chunk->inuse_count == 0)
            ++chunks_free;
        else if (chunk->inuse_count < chunk_capacity)
            ++chunks_partial;
        chunk = chunk->next;
    }

    stats->chunks_alloc += chunkCount;
    stats->chunks_inuse += chunkCount - chunks_free;
    stats->chunks_partial += chunks_partial;
    stats->chunks_free += chunks_free;

    stats->items_alloc += meter.alloc.level;
    stats->items_inuse += meter.inuse.level;
    stats->items_idle += meter.idle.level;

    stats->overhead += sizeof(MemPoolChunked) + chunkCount * sizeof(MemChunk) + strlen(objectType()) + 1;

    return meter.inuse.level;
}
