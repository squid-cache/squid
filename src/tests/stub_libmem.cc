/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "mem/libmem.la"
#include "STUB.h"

#include "mem/AllocatorProxy.h"
void *Mem::AllocatorProxy::alloc() {return xmalloc(64*1024);}
void Mem::AllocatorProxy::freeOne(void *address) {xfree(address);}
int Mem::AllocatorProxy::inUseCount() const {return 0;}
//static MemPoolMeter tmpMemPoolMeter;
//MemPoolMeter const &Mem::AllocatorProxy::getMeter() const STUB_RETVAL(tmpMemPoolMeter)
int Mem::AllocatorProxy::getStats(MemPoolStats * stats) STUB_RETVAL(0)

#include "mem/forward.h"
void Mem::Init() STUB_NOP
void Mem::Report() STUB_NOP
void Mem::Stats(StoreEntry *) STUB_NOP
void CleanIdlePools(void *) STUB_NOP
void Report(std::ostream &) STUB_NOP
void PoolReport(const MemPoolStats *, const MemPoolMeter *, std::ostream &) STUB_NOP
//const size_t squidSystemPageSize = 4096;
void memClean(void) STUB
void memInitModule(void) STUB
void memCleanModule(void) STUB
void memConfigure(void) STUB

void * memAllocate(mem_type type)
{
    // let's waste plenty of memory. This should cover any possible need
    return xmalloc(64*1024);
}

void *memAllocString(size_t net_size, size_t * gross_size) {return memAllocBuf(net_size, gross_size);}

void *
memAllocBuf(size_t net_size, size_t * gross_size)
{
    *gross_size=net_size;
    return xcalloc(1, net_size);
}

/* net_size is the new size, *gross size is the old gross size, to be changed to
 * the new gross size as a side-effect.
 */
void *
memReallocBuf(void *oldbuf, size_t net_size, size_t * gross_size)
{
    void *rv=xrealloc(oldbuf,net_size);
//    if (net_size > *gross_size)
//        memset(rv+net_size,0,net_size-*gross_size);
    *gross_size=net_size;
    return rv;
}

void memFree(void *p, int) {xfree(p);}
void memFreeString(size_t, void *buf) {xfree(buf);}
void memFreeBuf(size_t, void *buf) {xfree(buf);}
static void cxx_xfree(void * ptr) {xfree(ptr);}
FREE *memFreeBufFunc(size_t) {return cxx_xfree;}
int memInUse(mem_type) STUB_RETVAL(0)
void memDataInit(mem_type, const char *, size_t, int, bool) STUB_NOP
void memCheckInit(void) STUB_NOP

#include "mem/Pool.h"
MemPoolMeter::MemPoolMeter() STUB_NOP
void MemPoolMeter::flush() STUB
static MemPools tmpMemPools;
MemPools &MemPools::GetInstance() {return tmpMemPools;}
MemPools::MemPools() :
    pools(nullptr),
    mem_idle_limit(0),
    poolCount(0),
    defaultIsChunked(false)
{}
void MemPools::flushMeters() STUB
MemImplementingAllocator * MemPools::create(const char *label, size_t obj_size) STUB_RETVAL(NULL);
void MemPools::setIdleLimit(ssize_t new_idle_limit) STUB
ssize_t MemPools::idleLimit() const STUB_RETVAL(0)
void MemPools::clean(time_t maxage) STUB
void MemPools::setDefaultPoolChunking(bool const &) STUB

//MemAllocator::MemAllocator(char const *aLabel);
char const *MemAllocator::objectType() const STUB_RETVAL(NULL)
int MemAllocator::inUseCount() STUB_RETVAL(0)
size_t MemAllocator::RoundedSize(size_t minSize) STUB_RETVAL(minSize)

//MemImplementingAllocator::MemImplementingAllocator(char const *aLabel, size_t aSize) STUB_NOP
//MemImplementingAllocator::~MemImplementingAllocator();
MemPoolMeter const &MemImplementingAllocator::getMeter() const STUB_RETSTATREF(MemPoolMeter)
MemPoolMeter &MemImplementingAllocator::getMeter() STUB_RETSTATREF(MemPoolMeter)
void MemImplementingAllocator::flushMetersFull() STUB
void MemImplementingAllocator::flushMeters() STUB
void *MemImplementingAllocator::alloc() STUB_RETVAL(NULL)
void MemImplementingAllocator::freeOne(void *) STUB

MemPoolIterator * memPoolIterate(void) STUB_RETVAL(NULL)
MemImplementingAllocator * memPoolIterateNext(MemPoolIterator * iter) STUB_RETVAL(NULL)
void memPoolIterateDone(MemPoolIterator ** iter) STUB
int memPoolGetGlobalStats(MemPoolGlobalStats * stats) STUB_RETVAL(0)
int memPoolsTotalAllocated(void) STUB_RETVAL(0)

