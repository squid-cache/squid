/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _MEM_POOL_H_
#define _MEM_POOL_H_

/**
 \defgroup MemPoolsAPI  Memory Management (Memory Pool Allocator)
 \ingroup Components
 *
 *\par
 *  MemPools are a pooled memory allocator running on top of malloc(). It's
 *  purpose is to reduce memory fragmentation and provide detailed statistics
 *  on memory consumption.
 *
 \par
 *  Preferably all memory allocations in Squid should be done using MemPools
 *  or one of the types built on top of it (i.e. cbdata).
 *
 \note Usually it is better to use cbdata types as these gives you additional
 *     safeguards in references and typechecking. However, for high usage pools where
 *     the cbdata functionality of cbdata is not required directly using a MemPool
 *     might be the way to go.
 */

#include "mem/Meter.h"
#include "splay.h"
#include "util.h"

#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
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

/// \ingroup MemPoolsAPI
#define toMB(size) ( ((double) size) / ((double)(1024*1024)) )
/// \ingroup MemPoolsAPI
#define toKB(size) ( (size + 1024 - 1) / 1024 )

/// \ingroup MemPoolsAPI
#define MEM_PAGE_SIZE 4096
/// \ingroup MemPoolsAPI
#define MEM_MIN_FREE  32
/// \ingroup MemPoolsAPI
#define MEM_MAX_FREE  65535 /* unsigned short is max number of items per chunk */

class MemImplementingAllocator;
class MemPoolStats;

/// \ingroup MemPoolsAPI
/// \todo Kill this typedef for C++
typedef struct _MemPoolGlobalStats MemPoolGlobalStats;

/// \ingroup MemPoolsAPI
class MemPoolIterator
{
public:
    MemImplementingAllocator *pool;
    MemPoolIterator * next;
};

/**
 \ingroup MemPoolsAPI
 * Object to track per-pool cumulative counters
 */
class mgb_t
{
public:
    mgb_t() : count(0), bytes(0) {}
    double count;
    double bytes;
};

/**
 \ingroup MemPoolsAPI
 * Object to track per-pool memory usage (alloc = inuse+idle)
 */
class MemPoolMeter
{
public:
    MemPoolMeter();
    void flush();

    Mem::Meter alloc;
    Mem::Meter inuse;
    Mem::Meter idle;

    /** history Allocations */
    mgb_t gb_allocated;
    mgb_t gb_oallocated;

    /** account Saved Allocations */
    mgb_t gb_saved;

    /** account Free calls */
    mgb_t gb_freed;
};

class MemImplementingAllocator;

/// \ingroup MemPoolsAPI
class MemPools
{
public:
    static MemPools &GetInstance();
    MemPools();
    void flushMeters();

    /**
     \param label   Name for the pool. Displayed in stats.
     \param obj_size    Size of elements in MemPool.
     */
    MemImplementingAllocator * create(const char *label, size_t obj_size);

    /**
     * Sets upper limit in bytes to amount of free ram kept in pools. This is
     * not strict upper limit, but a hint. When MemPools are over this limit,
     * totally free chunks are immediately considered for release. Otherwise
     * only chunks that have not been referenced for a long time are checked.
     */
    void setIdleLimit(ssize_t new_idle_limit);
    ssize_t idleLimit() const;

    /**
     \par
     * Main cleanup handler. For MemPools to stay within upper idle limits,
     * this function needs to be called periodically, preferrably at some
     * constant rate, eg. from Squid event. It looks through all pools and
     * chunks, cleans up internal states and checks for releasable chunks.
     *
     \par
     * Between the calls to this function objects are placed onto internal
     * cache instead of returning to their home chunks, mainly for speedup
     * purpose. During that time state of chunk is not known, it is not
     * known whether chunk is free or in use. This call returns all objects
     * to their chunks and restores consistency.
     *
     \par
     * Should be called relatively often, as it sorts chunks in suitable
     * order as to reduce free memory fragmentation and increase chunk
     * utilisation.
     * Suitable frequency for cleanup is in range of few tens of seconds to
     * few minutes, depending of memory activity.
     *
     \todo DOCS: Re-write this shorter!
     *
     \param maxage   Release all totally idle chunks that
     *               have not been referenced for maxage seconds.
     */
    void clean(time_t maxage);

    void setDefaultPoolChunking(bool const &);
    MemImplementingAllocator *pools;
    ssize_t mem_idle_limit;
    int poolCount;
    bool defaultIsChunked;
};

/**
 \ingroup MemPoolsAPI
 * a pool is a [growing] space for objects of the same size
 */
class MemAllocator
{
public:
    MemAllocator (char const *aLabel);
    virtual ~MemAllocator() {}

    /**
     \param stats   Object to be filled with statistical data about pool.
     \retval        Number of objects in use, ie. allocated.
     */
    virtual int getStats(MemPoolStats * stats, int accumulate = 0) = 0;

    virtual MemPoolMeter const &getMeter() const = 0;

    /**
     * Allocate one element from the pool
     */
    virtual void *alloc() = 0;

    /**
     * Free a element allocated by MemAllocator::alloc()
     */
    virtual void freeOne(void *) = 0;

    virtual char const *objectType() const;
    virtual size_t objectSize() const = 0;
    virtual int getInUseCount() = 0;
    void zeroBlocks(bool doIt) {doZero = doIt;}
    int inUseCount();

    /**
     * Allows you tune chunk size of pooling. Objects are allocated in chunks
     * instead of individually. This conserves memory, reduces fragmentation.
     * Because of that memory can be freed also only in chunks. Therefore
     * there is tradeoff between memory conservation due to chunking and free
     * memory fragmentation.
     *
     \note  As a general guideline, increase chunk size only for pools that keep
     *      very many items for relatively long time.
     */
    virtual void setChunkSize(size_t) {}

    /**
     \param minSize Minimum size needed to be allocated.
     \retval n Smallest size divisible by sizeof(void*)
     */
    static size_t RoundedSize(size_t minSize);

protected:
    /** Whether to zero memory on initial allocation and on return to the pool.
     *
     * We do this on some pools because many object constructors are/were incomplete
     * and we are afraid some code may use the object after free.
     * These probems are becoming less common, so when possible set this to false.
     */
    bool doZero;

private:
    const char *label;
};

/// \ingroup MemPoolsAPI
class MemImplementingAllocator : public MemAllocator
{
public:
    MemImplementingAllocator(char const *aLabel, size_t aSize);
    virtual ~MemImplementingAllocator();
    virtual MemPoolMeter const &getMeter() const;
    virtual MemPoolMeter &getMeter();
    virtual void flushMetersFull();
    virtual void flushMeters();

    /**
     * Allocate one element from the pool
     */
    virtual void *alloc();

    /**
     * Free a element allocated by MemImplementingAllocator::alloc()
     */
    virtual void freeOne(void *);

    virtual bool idleTrigger(int shift) const = 0;
    virtual void clean(time_t maxage) = 0;
    virtual size_t objectSize() const;
    virtual int getInUseCount() = 0;
protected:
    virtual void *allocate() = 0;
    virtual void deallocate(void *, bool aggressive) = 0;
    MemPoolMeter meter;
    int memPID;
public:
    MemImplementingAllocator *next;
public:
    size_t alloc_calls;
    size_t free_calls;
    size_t saved_calls;
    size_t obj_size;
};

/// \ingroup MemPoolsAPI
class MemPoolStats
{
public:
    MemAllocator *pool;
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

/// \ingroup MemPoolsAPI
/// \todo Classify and add constructor/destructor to initialize properly.
struct _MemPoolGlobalStats {
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
    ssize_t mem_idle_limit;
};

/// \ingroup MemPoolsAPI
/// Creates a named MemPool of elements with the given size
#define memPoolCreate MemPools::GetInstance().create

/* Allocator API */
/**
 \ingroup MemPoolsAPI
 * Initialise iteration through all of the pools.
 * \returns Iterator for use by memPoolIterateNext() and memPoolIterateDone()
 */
extern MemPoolIterator * memPoolIterate(void);

/**
 \ingroup MemPoolsAPI
 * Get next pool pointer, until getting NULL pointer.
 */
extern MemImplementingAllocator * memPoolIterateNext(MemPoolIterator * iter);

/**
 \ingroup MemPoolsAPI
 * Should be called after finished with iterating through all pools.
 */
extern void memPoolIterateDone(MemPoolIterator ** iter);

/**
 \ingroup MemPoolsAPI
 \todo Stats API - not sured how to refactor yet
 *
 * Fills a MemPoolGlobalStats with statistical data about overall
 * usage for all pools.
 *
 * \param stats   Object to be filled with statistical data.
 *
 * \return Number of pools that have at least one object in use.
 *        Ie. number of dirty pools.
 */
extern int memPoolGetGlobalStats(MemPoolGlobalStats * stats);

/// \ingroup MemPoolsAPI
extern int memPoolsTotalAllocated(void);

#endif /* _MEM_POOL_H_ */

