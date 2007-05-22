
#ifndef _MEM_POOLS_H_
#define _MEM_POOLS_H_

#include "config.h"
#include "assert.h"
#include "util.h"

#include "memMeter.h"
#include "splay.h"

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

#define MB ((size_t)1024*1024)
#define mem_unlimited_size 2 * 1024 * MB
#define toMB(size) ( ((double) size) / MB )
#define toKB(size) ( (size + 1024 - 1) / 1024 )

#define MEM_PAGE_SIZE 4096
#define MEM_CHUNK_SIZE 4096 * 4
#define MEM_CHUNK_MAX_SIZE  256 * 1024	/* 2MB */
#define MEM_MIN_FREE  32
#define MEM_MAX_FREE  65535	/* ushort is max number of items per chunk */

class MemImplementingAllocator;
class MemChunk;
class MemPoolStats;

typedef struct _MemPoolGlobalStats MemPoolGlobalStats;

class MemPoolIterator
{
  public:
    MemImplementingAllocator *pool;
    MemPoolIterator * next;
};

/* object to track per-pool cumulative counters */

class mgb_t
{
  public:
    mgb_t() : count(0), bytes(0){}
    double count;
    double bytes;
};

/* object to track per-pool memory usage (alloc = inuse+idle) */

class MemPoolMeter
{
  public:
    void flush();
    MemMeter alloc;
    MemMeter inuse;
    MemMeter idle;
    mgb_t gb_saved;		/* account Allocations */
    mgb_t gb_osaved;		/* history Allocations */
    mgb_t gb_freed;		/* account Free calls */
};

class MemImplementingAllocator;

class MemPools 
{
  public:
    static MemPools &GetInstance();
    MemPools();
    void init();
    void flushMeters();
    MemImplementingAllocator * create(const char *label, size_t obj_size);
    MemImplementingAllocator * create(const char *label, size_t obj_size, bool const chunked);
    void setIdleLimit(size_t new_idle_limit);
    size_t const idleLimit() const;
    void clean(time_t maxage);
    void setDefaultPoolChunking(bool const &);
    MemImplementingAllocator *pools;
    int mem_idle_limit;
    int poolCount;
    bool defaultIsChunked;
  private:
    static MemPools *Instance;
};

/* a pool is a [growing] space for objects of the same size */

class MemAllocator
{
public:
    MemAllocator (char const *aLabel);
    virtual ~MemAllocator() {}
    virtual int getStats(MemPoolStats * stats) = 0;
    virtual MemPoolMeter const &getMeter() const = 0;
    virtual void *alloc() = 0;
    virtual void free(void *) = 0;
    virtual char const *objectType() const;
    virtual size_t objectSize() const = 0;
    virtual int getInUseCount() = 0;
    int inUseCount();
    virtual void setChunkSize(size_t chunksize) {}

    // smallest size divisible by sizeof(void*) and at least minSize
    static size_t RoundedSize(size_t minSize);
private:
    const char *label;
};

/* Support late binding of pool type for allocator agnostic classes */
class MemAllocatorProxy
{
  public:
    inline MemAllocatorProxy(char const *aLabel, size_t const &);
    void *alloc();
    void free(void *);
    int inUseCount() const;
    size_t objectSize() const;
    MemPoolMeter const &getMeter() const;
    int getStats(MemPoolStats * stats);
    char const * objectType() const;
  private:
    MemAllocator *getAllocator() const;
    const char *label;
    size_t size;
    mutable MemAllocator *theAllocator;
};
/* help for classes */
/* Put this in the class */
#define MEMPROXY_CLASS(CLASS) \
/* TODO change syntax to allow moving into .cci files */ \
    inline void *operator new(size_t); \
    inline void operator delete(void *); \
    static inline MemAllocatorProxy &Pool()

/* put this in the class .h, or .cci as appropriate */
#define MEMPROXY_CLASS_INLINE(CLASS) \
MemAllocatorProxy& CLASS::Pool() \
{ \
    static MemAllocatorProxy thePool(#CLASS, sizeof (CLASS)); \
    return thePool; \
} \
\
void * \
CLASS::operator new (size_t byteCount) \
{ \
    /* derived classes with different sizes must implement their own new */ \
    assert (byteCount == sizeof (CLASS)); \
\
    return Pool().alloc(); \
}  \
\
void \
CLASS::operator delete (void *address) \
{ \
    Pool().free(address); \
}

class MemImplementingAllocator : public MemAllocator
{
  public:
    MemImplementingAllocator(char const *aLabel, size_t aSize);
    virtual MemPoolMeter const &getMeter() const;
    virtual MemPoolMeter &getMeter();
    virtual void flushMetersFull();
    virtual void flushMeters();
    virtual void *alloc();
    virtual void free(void *);
    virtual bool idleTrigger(int shift) const = 0;
    virtual void clean(time_t maxage) = 0;
    /* Hint to the allocator - may be ignored */
    virtual void setChunkSize(size_t chunksize) {}
    virtual size_t objectSize() const;
    virtual int getInUseCount() = 0;
  protected:
    virtual void *allocate() = 0;
    virtual void deallocate(void *) = 0;
  private:
    MemPoolMeter meter;
  public:
    MemImplementingAllocator *next;
  public:
    size_t alloc_calls;
    size_t free_calls;
    size_t obj_size;
};

class MemPool : public MemImplementingAllocator
{
  public:
    friend class MemChunk;
    MemPool(const char *label, size_t obj_size);
    ~MemPool();
    void convertFreeCacheToChunkFreeCache();
    virtual void clean(time_t maxage);
    virtual int getStats(MemPoolStats * stats);
    void createChunk();
    void *get();
    void push(void *obj);
    virtual int getInUseCount();
  protected:
    virtual void *allocate();
    virtual void deallocate(void *);
  public:
    virtual void setChunkSize(size_t chunksize);
    virtual bool idleTrigger(int shift) const;

    size_t chunk_size;
    int chunk_capacity;
    int memPID;
    int chunkCount;
    size_t inuse;
    size_t idle;
    void *freeCache;
    MemChunk *nextFreeChunk;
    MemChunk *Chunks;
    Splay<MemChunk *> allChunks;
};

class MemMalloc : public MemImplementingAllocator
{
  public:
    MemMalloc(char const *label, size_t aSize);
    virtual bool idleTrigger(int shift) const;
    virtual void clean(time_t maxage);
    virtual int getStats(MemPoolStats * stats);
    virtual int getInUseCount();
  protected:
    virtual void *allocate();
    virtual void deallocate(void *);
  private:
    int inuse;
};

class MemChunk
{
  public:
    MemChunk(MemPool *pool);
    ~MemChunk();
    void *freeList;
    void *objCache;
    int inuse_count;
    MemChunk *nextFreeChunk;
    MemChunk *next;
    time_t lastref;
    MemPool *pool;
};

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

#define memPoolCreate MemPools::GetInstance().create

/* Allocator API */
extern MemPoolIterator * memPoolIterate(void);
extern MemImplementingAllocator * memPoolIterateNext(MemPoolIterator * iter);
extern void memPoolIterateDone(MemPoolIterator ** iter);

/* Stats API - not sured how to refactor yet */
extern int memPoolGetGlobalStats(MemPoolGlobalStats * stats);

extern int memPoolInUseCount(MemAllocator *);
extern int memPoolsTotalAllocated(void);

MemAllocatorProxy::MemAllocatorProxy(char const *aLabel, size_t const &aSize) : label (aLabel), size(aSize), theAllocator (NULL)
{
}


#endif /* _MEM_POOLS_H_ */
