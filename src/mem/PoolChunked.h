/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_MEM_POOLCHUNKED_H
#define SQUID__SRC_MEM_POOLCHUNKED_H

#include "mem/AllocatorMetrics.h"
#include "splay.h"

namespace Mem
{

/// details about one chunk of memory
class Chunk
{
public:
    static const size_t MinSize = 4 * 4096; ///< 16KB ... 4 * VM_PAGE_SZ
    static const size_t MaxSize = 256 * 1024; ///< 256KB

    Chunk(PoolChunked *);
    ~Chunk();

    void *freeList = nullptr;
    void *objCache = nullptr;
    int inuse_count = 0;
    Chunk *nextFreeChunk = nullptr;
    Chunk *next = nullptr;
    time_t lastref = 0;
    PoolChunked *pool = nullptr;
};

class PoolChunked : public AllocatorMetrics
{
public:
    friend class Chunk;
    PoolChunked(const char *label, size_t obj_size);
    ~PoolChunked();

    void convertFreeCacheToChunkFreeCache();

    void createChunk();
    void *get();
    void push(void *);

    /* Mem::AllocatorBase API */
    virtual int getStats(MemPoolStats *);
    virtual int getInUseCount();
    virtual void setChunkSize(size_t);

    /* MemImplementingAllocator API */
    virtual bool idleTrigger(int) const;
    virtual void clean(time_t);
protected:
    virtual void *allocate();
    virtual void deallocate(void *, bool);

public:
    size_t chunk_size = Chunk::MinSize;
    int chunk_capacity = 0;
    int chunkCount = 0;
    void *freeCache = nullptr;
    Chunk *nextFreeChunk = nullptr;
    Chunk *Chunks = nullptr;
    Splay<Mem::Chunk *> allChunks; // XXX: move away from splay
};

} // namespace Mem

#endif /* SQUID__SRC_MEM_POOLCHUNKED_H */
