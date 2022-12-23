/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Alex Rousskov, Andres Kroonmaa, Robert Collins
 */

#include "squid.h"
#include "mem/PoolChunked.h"
#include "mem/Stats.h"

#include <cassert>
#include <cstring>

#define MEM_MAX_MMAP_CHUNKS 2048
#define MEM_PAGE_SIZE 4096
#define MEM_MIN_FREE  32
#define MEM_MAX_FREE  65535 /* unsigned short is max number of items per chunk */

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
     * note that this requires:
     * allocate one chunk for the pool of chunks's first chunk
     * allocate a chunk from that pool
     * move the contents of one chunk into the other
     * free the first chunk.
     */
    inuse_count = 0;
    next = nullptr;
    pool = aPool;

    if (pool->doZero)
        objCache = xcalloc(1, pool->chunk_size);
    else
        objCache = xmalloc(pool->chunk_size);

    freeList = objCache;
    void **Free = (void **)freeList;

    for (int i = 1; i < pool->chunk_capacity; ++i) {
        *Free = (void *) ((char *) Free + pool->objectSize);
        void **nextFree = (void **)*Free;
        (void) VALGRIND_MAKE_MEM_NOACCESS(Free, pool->objectSize);
        Free = nextFree;
    }
    nextFreeChunk = pool->nextFreeChunk;
    pool->nextFreeChunk = this;

    pool->meter.alloc += pool->chunk_capacity;
    pool->meter.idle += pool->chunk_capacity;
    ++pool->chunkCount;
    lastref = squid_curtime;
    pool->allChunks.insert(this, memCompChunks);
}

MemPoolChunked::MemPoolChunked(const char *aLabel, size_t aSize) :
    Mem::Allocator(aLabel, aSize),
    chunk_size(0),
    chunk_capacity(0), chunkCount(0), freeCache(nullptr), nextFreeChunk(nullptr),
    Chunks(nullptr), allChunks(Splay<MemChunk *>())
{
    setChunkSize(MEM_CHUNK_SIZE);

#if HAVE_MALLOPT && M_MMAP_MAX
    mallopt(M_MMAP_MAX, MEM_MAX_MMAP_CHUNKS);
#endif
}

MemChunk::~MemChunk()
{
    pool->meter.alloc -= pool->chunk_capacity;
    pool->meter.idle -= pool->chunk_capacity;
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
        memset(obj, 0, objectSize);
    Free = (void **)obj;
    *Free = freeCache;
    freeCache = obj;
    (void) VALGRIND_MAKE_MEM_NOACCESS(obj, objectSize);
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

    ++countSavedAllocs;

    /* first, try cache */
    if (freeCache) {
        Free = (void **)freeCache;
        (void) VALGRIND_MAKE_MEM_DEFINED(Free, objectSize);
        freeCache = *Free;
        *Free = nullptr;
        return Free;
    }
    /* then try perchunk freelist chain */
    if (nextFreeChunk == nullptr) {
        /* no chunk with frees, so create new one */
        --countSavedAllocs; // compensate for the ++ above
        createChunk();
    }
    /* now we have some in perchunk freelist chain */
    MemChunk *chunk = nextFreeChunk;

    Free = (void **)chunk->freeList;
    chunk->freeList = *Free;
    *Free = nullptr;
    ++chunk->inuse_count;
    chunk->lastref = squid_curtime;

    if (chunk->freeList == nullptr) {
        /* last free in this chunk, so remove us from perchunk freelist chain */
        nextFreeChunk = chunk->nextFreeChunk;
    }
    (void) VALGRIND_MAKE_MEM_DEFINED(Free, objectSize);
    return Free;
}

/* just create a new chunk and place it into a good spot in the chunk chain */
void
MemPoolChunked::createChunk()
{
    MemChunk *chunk, *newChunk;

    newChunk = new MemChunk(this);

    chunk = Chunks;
    if (chunk == nullptr) {    /* first chunk in pool */
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

/**
 * Allows you tune chunk size of pooling. Objects are allocated in chunks
 * instead of individually. This conserves memory, reduces fragmentation.
 * Because of that memory can be freed also only in chunks. Therefore
 * there is tradeoff between memory conservation due to chunking and free
 * memory fragmentation.
 *
 * \note  As a general guideline, increase chunk size only for pools that keep
 *        very many items for relatively long time.
 */
void
MemPoolChunked::setChunkSize(size_t chunksize)
{
    int cap;
    size_t csize = chunksize;

    if (Chunks)     /* unsafe to tamper */
        return;

    csize = ((csize + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE) * MEM_PAGE_SIZE;  /* round up to page size */
    cap = csize / objectSize;

    if (cap < MEM_MIN_FREE)
        cap = MEM_MIN_FREE;
    if (cap * objectSize > MEM_CHUNK_MAX_SIZE)
        cap = MEM_CHUNK_MAX_SIZE / objectSize;
    if (cap > MEM_MAX_FREE)
        cap = MEM_MAX_FREE;
    if (cap < 1)
        cap = 1;

    csize = cap * objectSize;
    csize = ((csize + MEM_PAGE_SIZE - 1) / MEM_PAGE_SIZE) * MEM_PAGE_SIZE;  /* round up to page size */
    cap = csize / objectSize;

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

    flushCounters();
    clean(0);
    assert(getInUseCount() == 0);

    chunk = Chunks;
    while ( (fchunk = chunk) != nullptr) {
        chunk = chunk->next;
        delete fchunk;
    }
    /* TODO we should be doing something about the original Chunks pointer here. */

}

void *
MemPoolChunked::allocate()
{
    void *p = get();
    assert(meter.idle.currentLevel() > 0);
    --meter.idle;
    ++meter.inuse;
    return p;
}

void
MemPoolChunked::deallocate(void *obj)
{
    push(obj);
    assert(meter.inuse.currentLevel() > 0);
    --meter.inuse;
    ++meter.idle;
}

void
MemPoolChunked::convertFreeCacheToChunkFreeCache()
{
    void *Free;
    /*
     * OK, so we have to go through all the global freeCache and find the Chunk
     * any given Free belongs to, and stuff it into that Chunk's freelist
     */

    while ((Free = freeCache) != nullptr) {
        MemChunk *chunk = nullptr;
        chunk = const_cast<MemChunk *>(*allChunks.find(Free, memCompObjChunks));
        assert(splayLastResult == 0);
        assert(chunk->inuse_count > 0);
        -- chunk->inuse_count;
        (void) VALGRIND_MAKE_MEM_DEFINED(Free, sizeof(void *));
        freeCache = *(void **)Free; /* remove from global cache */
        *(void **)Free = chunk->freeList;   /* stuff into chunks freelist */
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

    if (!Chunks)
        return;

    flushCounters();
    convertFreeCacheToChunkFreeCache();
    /* Now we have all chunks in this pool cleared up, all free items returned to their home */
    /* We start now checking all chunks to see if we can release any */
    /* We start from Chunks->next, so first chunk is not released */
    /* Recreate nextFreeChunk list from scratch */

    chunk = Chunks;
    while ((freechunk = chunk->next) != nullptr) {
        age = squid_curtime - freechunk->lastref;
        freechunk->nextFreeChunk = nullptr;
        if (freechunk->inuse_count == 0)
            if (age >= maxage) {
                chunk->next = freechunk->next;
                delete freechunk;
                freechunk = nullptr;
            }
        if (chunk->next == nullptr)
            break;
        chunk = chunk->next;
    }

    /* Recreate nextFreeChunk list from scratch */
    /* Populate nextFreeChunk list in order of "most filled chunk first" */
    /* in case of equal fill, put chunk in lower ram first */
    /* First (create time) chunk is always on top, no matter how full */

    chunk = Chunks;
    nextFreeChunk = chunk;
    chunk->nextFreeChunk = nullptr;

    while (chunk->next) {
        chunk->next->nextFreeChunk = nullptr;
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
    return meter.idle.currentLevel() > (chunk_capacity << shift);
}

size_t
MemPoolChunked::getStats(Mem::PoolStats &stats)
{
    MemChunk *chunk;
    int chunks_free = 0;
    int chunks_partial = 0;

    clean((time_t) 555555); /* don't want to get chunks released before reporting */

    stats.pool = this;
    stats.label = label;
    stats.meter = &meter;
    stats.obj_size = objectSize;
    stats.chunk_capacity = chunk_capacity;

    /* gather stats for each Chunk */
    chunk = Chunks;
    while (chunk) {
        if (chunk->inuse_count == 0)
            ++chunks_free;
        else if (chunk->inuse_count < chunk_capacity)
            ++chunks_partial;
        chunk = chunk->next;
    }

    stats.chunks_alloc += chunkCount;
    stats.chunks_inuse += chunkCount - chunks_free;
    stats.chunks_partial += chunks_partial;
    stats.chunks_free += chunks_free;

    stats.items_alloc += meter.alloc.currentLevel();
    stats.items_inuse += meter.inuse.currentLevel();
    stats.items_idle += meter.idle.currentLevel();

    stats.overhead += sizeof(MemPoolChunked) + chunkCount * sizeof(MemChunk) + strlen(label) + 1;

    return getInUseCount();
}

