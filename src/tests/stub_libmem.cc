/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "mem/libmem.la"
#include "tests/STUB.h"

#include "mem/AllocatorBase.h"
size_t Mem::AllocatorBase::RoundedSize(size_t minSize) STUB_RETVAL(minSize)

#include "mem/AllocatorMetrics.h"
namespace Mem
{
void PoolMeter::flush() STUB
//AllocatorMetrics::AllocatorMetrics(char const *, size_t) STUB_NOP
//AllocatorMetrics::~AllocatorMetrics();
void AllocatorMetrics::flushMetersFull() STUB
void AllocatorMetrics::flushMeters() STUB
void *AllocatorMetrics::alloc() STUB_RETVAL(nullptr)
void AllocatorMetrics::freeOne(void *) STUB
}

#include "mem/AllocatorProxy.h"
void *Mem::AllocatorProxy::alloc() {return xmalloc(64*1024);}
void Mem::AllocatorProxy::freeOne(void *address) {xfree(address);}
int Mem::AllocatorProxy::getInUseCount() const {return 0;}
//static Mem::PoolMeter tmpMemPoolMeter;
//Mem::PoolMeter const &Mem::AllocatorProxy::getMeter() const STUB_RETVAL(tmpMemPoolMeter)
int Mem::AllocatorProxy::getStats(PoolStats *) STUB_RETVAL(0)

#include "mem/forward.h"
void Mem::Init() STUB_NOP
void Mem::Report() STUB_NOP
void Mem::Stats(StoreEntry *) STUB_NOP
void Mem::CleanIdlePools(void *) STUB_NOP
void Mem::Report(std::ostream &) STUB_NOP
void Mem::PoolReport(const PoolStats *, const PoolMeter *, std::ostream &) STUB_NOP
//const size_t squidSystemPageSize = 4096;
void memClean(void) STUB
void memInitModule(void) STUB
void memCleanModule(void) STUB
void memConfigure(void) STUB

void *memAllocate(mem_type)
{
    // let's waste plenty of memory. This should cover any possible need
    return xmalloc(64*1024);
}

void *memAllocString(size_t net_size, size_t * gross_size) {return memAllocBuf(net_size, gross_size);}

void *memAllocRigid(size_t net_size)
{
    return xmalloc(net_size);
}

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
void memFreeRigid(void *buf, size_t) {xfree(buf);}
void memFreeBuf(size_t, void *buf) {xfree(buf);}
static void cxx_xfree(void * ptr) {xfree(ptr);}
FREE *memFreeBufFunc(size_t) {return cxx_xfree;}
int memInUse(mem_type) STUB_RETVAL(0)
void memDataInit(mem_type, const char *, size_t, int, bool) STUB_NOP
void memCheckInit(void) STUB_NOP

//#include "mem/Meter.h"
#include "mem/Pool.h"
int memPoolGetGlobalStats(MemPoolGlobalStats *) STUB_RETVAL(0)
int memPoolsTotalAllocated(void) STUB_RETVAL(0)

//#include "mem/Stats.h"
#include "mem/PoolsManager.h"
namespace Mem
{
PoolsManager::PoolsManager() STUB_NOP
static PoolsManager tmpMemPools;
PoolsManager &PoolsManager::GetInstance() {return tmpMemPools;}
AllocatorMetrics * PoolsManager::create(const char *, size_t) STUB_RETVAL(nullptr);
void PoolsManager::clean(time_t) STUB
void PoolsManager::flushMeters() STUB
}
