/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 13    High Level Memory Pool Management */

#ifndef _SQUID_SRC_MEM_FORWARD_H
#define _SQUID_SRC_MEM_FORWARD_H

/* for mem_type */
#include "enums.h"
#include "mem/AllocatorProxy.h"
/* for FREE */
#include "typedefs.h"

#include <iosfwd>

class StoreEntry;
class MemPoolStats;
class MemPoolMeter;

namespace Mem
{
    void Init();
    void Report();
    void Stats(StoreEntry *);
    void CleanIdlePools(void *unused);
    void Report(std::ostream &);
    void PoolReport(const MemPoolStats * mp_st, const MemPoolMeter * AllMeter, std::ostream &);
};

extern const size_t squidSystemPageSize;

void memClean(void);
void memInitModule(void);
void memCleanModule(void);
void memConfigure(void);
void *memAllocate(mem_type);
void *memAllocString(size_t net_size, size_t * gross_size);
void *memAllocBuf(size_t net_size, size_t * gross_size);
void *memReallocBuf(void *buf, size_t net_size, size_t * gross_size);
void memFree(void *, int type);
void memFreeString(size_t size, void *);
void memFreeBuf(size_t size, void *);
FREE *memFreeBufFunc(size_t size);
int memInUse(mem_type);
void memDataInit(mem_type, const char *, size_t, int, bool doZero = true);
void memCheckInit(void);

#endif /* _SQUID_SRC_MEM_FORWARD_H */
