/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _MEM_POOL_CHUNKED_H_
#define _MEM_POOL_CHUNKED_H_

#include "mem/Pool.h"
#include "splay.h"

#define MEM_CHUNK_SIZE        4 * 4096  /* 16KB ... 4 * VM_PAGE_SZ */
#define MEM_CHUNK_MAX_SIZE  256 * 1024  /* 2MB */

class MemChunk;

/// \ingroup MemPoolsAPI
class MemPoolChunked : public MemImplementingAllocator
{
public:
    friend class MemChunk;
    MemPoolChunked(const char *label, size_t obj_size);
    ~MemPoolChunked();
    void convertFreeCacheToChunkFreeCache();
    virtual void clean(time_t maxage);

    /**
     \param stats   Object to be filled with statistical data about pool.
     \retval        Number of objects in use, ie. allocated.
     */
    virtual int getStats(MemPoolStats * stats, int accumulate);

    void createChunk();
    void *get();
    void push(void *obj);
    virtual int getInUseCount();
protected:
    virtual void *allocate();
    virtual void deallocate(void *, bool aggressive);
public:
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
    virtual void setChunkSize(size_t chunksize);

    virtual bool idleTrigger(int shift) const;

    size_t chunk_size;
    int chunk_capacity;
    int chunkCount;
    void *freeCache;
    MemChunk *nextFreeChunk;
    MemChunk *Chunks;
    Splay<MemChunk *> allChunks;
};

/// \ingroup MemPoolsAPI
class MemChunk
{
public:
    MemChunk(MemPoolChunked *pool);
    ~MemChunk();
    void *freeList;
    void *objCache;
    int inuse_count;
    MemChunk *nextFreeChunk;
    MemChunk *next;
    time_t lastref;
    MemPoolChunked *pool;
};

#endif /* _MEM_POOL_CHUNKED_H_ */

