
#ifndef _MEM_POOLS_H_
#define _MEM_POOLS_H_

#include "config.h"
#include "util.h"
#ifdef __cplusplus

template <class V>

class SplayNode;

typedef SplayNode<void *> splayNode;

#else
#include "splay.h"
#endif
#include "memMeter.h"

#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif

#if HAVE_MEMORY_H
#include <memory.h>
#endif

#if !M_MMAP_MAX
#if USE_DLMALLOC
#define M_MMAP_MAX -4
#endif
#endif

#if PURIFY
#define DISABLE_POOLS 1		/* Disabling Memory pools under purify */
#endif

#define MB ((size_t)1024*1024)
#define mem_unlimited_size 2 * 1024 * MB
#define toMB(size) ( ((double) size) / MB )
#define toKB(size) ( (size + 1024 - 1) / 1024 )

#define MEM_PAGE_SIZE 4096
#define MEM_CHUNK_SIZE 4096 * 4
#define MEM_CHUNK_MAX_SIZE  256 * 1024	/* 2MB */
#define MEM_MIN_FREE  32
#define MEM_MAX_FREE  65535	/* ushort is max number of items per chunk */

typedef struct _MemPoolMeter MemPoolMeter;

typedef struct _MemPool MemPool;

typedef struct _MemChunk MemChunk;

typedef struct _MemPoolStats MemPoolStats;

typedef struct _MemPoolGlobalStats MemPoolGlobalStats;

typedef struct _MemPoolIterator MemPoolIterator;

struct _MemPoolIterator
{
    MemPool *pool;
    MemPoolIterator * next;
};

/* object to track per-pool cumulative counters */

typedef struct
{
    double count;
    double bytes;
}

mgb_t;

/* object to track per-pool memory usage (alloc = inuse+idle) */

struct _MemPoolMeter
{
    MemMeter alloc;
    MemMeter inuse;
    MemMeter idle;
    mgb_t gb_saved;		/* account Allocations */
    mgb_t gb_osaved;		/* history Allocations */
    mgb_t gb_freed;		/* account Free calls */
};

/* a pool is a [growing] space for objects of the same size */

struct _MemPool
{
    const char *label;
    size_t obj_size;
    size_t chunk_size;
    int chunk_capacity;
    int memPID;
    int chunkCount;
    size_t alloc_calls;
    size_t free_calls;
    size_t inuse;
    size_t idle;
    void *freeCache;
    MemChunk *nextFreeChunk;
    MemChunk *Chunks;
    MemPoolMeter meter;
    splayNode *allChunks;
    MemPool *next;
};

struct _MemChunk
{
    void *freeList;
    void *objCache;
    int inuse_count;
    MemChunk *nextFreeChunk;
    MemChunk *next;
    time_t lastref;
};

struct _MemPoolStats
{
    MemPool *pool;
    const char *label;
    MemPoolMeter *meter;
    int obj_size;
    int chunk_capacity;
    int chunk_size;

    int chunks_alloc;
    int chunks_inuse;
    int chunks_partial;
    int chunks_free;

    int items_alloc;
    int items_inuse;
    int items_idle;

    int overhead;
};

struct _MemPoolGlobalStats
{
    MemPoolMeter *TheMeter;

    int tot_pools_alloc;
    int tot_pools_inuse;
    int tot_pools_mempid;

    int tot_chunks_alloc;
    int tot_chunks_inuse;
    int tot_chunks_partial;
    int tot_chunks_free;

    int tot_items_alloc;
    int tot_items_inuse;
    int tot_items_idle;

    int tot_overhead;
    int mem_idle_limit;
};

#define SIZEOF_CHUNK  ( ( sizeof(MemChunk) + sizeof(double) -1) / sizeof(double) ) * sizeof(double);

/* memPools */

/* Allocator API */
SQUIDCEXTERN MemPool *memPoolCreate(const char *label, size_t obj_size);
SQUIDCEXTERN void *memPoolAlloc(MemPool * pool);
SQUIDCEXTERN void memPoolFree(MemPool * pool, void *obj);
SQUIDCEXTERN void memPoolDestroy(MemPool ** pool);

SQUIDCEXTERN MemPoolIterator * memPoolIterate(void);
SQUIDCEXTERN MemPool * memPoolIterateNext(MemPoolIterator * iter);
SQUIDCEXTERN void memPoolIterateDone(MemPoolIterator ** iter);

/* Tune API */
SQUIDCEXTERN void memPoolSetChunkSize(MemPool * pool, size_t chunksize);
SQUIDCEXTERN void memPoolSetIdleLimit(size_t new_idle_limit);

/* Stats API */
SQUIDCEXTERN int memPoolGetStats(MemPoolStats * stats, MemPool * pool);
SQUIDCEXTERN int memPoolGetGlobalStats(MemPoolGlobalStats * stats);

/* Module housekeeping API */
SQUIDCEXTERN void memPoolClean(time_t maxage);

#if UNUSED
/* Stats history API */
SQUIDCEXTERN void memPoolCheckRates(); /* stats history checkpoints */
#endif

#endif /* _MEM_POOLS_H_ */
