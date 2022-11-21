/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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

#include "mem/Allocator.h"
#include "mem/Meter.h"
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
class MemPoolIterator
{
public:
    MemImplementingAllocator *pool;
    MemPoolIterator * next;
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
     * deallocate attempts to release memory to the system instead of pooling.
     */
    void setIdleLimit(const ssize_t newLimit) { idleLimit_ = newLimit; }
    /// \copydoc idleLimit_
    ssize_t idleLimit() const { return idleLimit_; }

    /**
     \par
     * Main cleanup handler. For MemPools to stay within upper idle limits,
     * this function needs to be called periodically, preferably at some
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
     * TODO: DOCS: Re-write this shorter!
     *
     \param maxage   Release all totally idle chunks that
     *               have not been referenced for maxage seconds.
     */
    void clean(time_t maxage);

    void setDefaultPoolChunking(bool const &);

    MemImplementingAllocator *pools = nullptr;
    int poolCount = 0;
    bool defaultIsChunked = false;

private:
    /// Limits the cumulative size of allocated (but unused) memory in all pools.
    /// Initial value is 2MB until first configuration,
    /// See squid.conf memory_pools_limit directive.
    ssize_t idleLimit_ = (2 << 20);
};

/// \ingroup MemPoolsAPI
class MemImplementingAllocator : public Mem::Allocator
{
public:
    typedef Mem::PoolMeter PoolMeter; // TODO remove

    MemImplementingAllocator(char const *aLabel, size_t aSize);
    virtual ~MemImplementingAllocator();

    virtual PoolMeter &getMeter();
    virtual void flushMetersFull();
    virtual void flushMeters();
    virtual bool idleTrigger(int shift) const = 0;
    virtual void clean(time_t maxage) = 0;

    /* Mem::Allocator API */
    virtual PoolMeter const &getMeter() const;
    virtual void *alloc();
    virtual void freeOne(void *);
    virtual size_t objectSize() const;
    virtual int getInUseCount() = 0;

protected:
    virtual void *allocate() = 0;
    virtual void deallocate(void *, bool aggressive) = 0;
    PoolMeter meter;
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
    typedef Mem::PoolMeter PoolMeter; // TODO remove
    typedef Mem::Allocator Allocator; // TODO remove

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

/// \ingroup MemPoolsAPI
class MemPoolGlobalStats
{
public:
    typedef Mem::PoolMeter PoolMeter; // TODO remove

    PoolMeter *TheMeter = nullptr;

    int tot_pools_alloc = 0;
    int tot_pools_inuse = 0;

    int tot_chunks_alloc = 0;
    int tot_chunks_inuse = 0;
    int tot_chunks_partial = 0;
    int tot_chunks_free = 0;

    int tot_items_alloc = 0;
    int tot_items_inuse = 0;
    int tot_items_idle = 0;

    int tot_overhead = 0;
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

