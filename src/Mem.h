/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 13    High Level Memory Pool Management */

#ifndef SQUID_MEM
#define SQUID_MEM

/* for mem_type */
#include "enums.h"
/* for FREE */
#include "typedefs.h"

#include <iosfwd>

class StoreEntry;
class MemPoolStats;
class MemPoolMeter;

class Mem
{

public:
    static void Init();
    static void Report();
    static void Stats(StoreEntry *);
    static void CleanIdlePools(void *unused);
    static void Report(std::ostream &);
    static void PoolReport(const MemPoolStats * mp_st, const MemPoolMeter * AllMeter, std::ostream &);

protected:
    static void RegisterWithCacheManager(void);
};

extern const size_t squidSystemPageSize;

/// Main cleanup handler.
void memClean(void);
void memInitModule(void);
void memCleanModule(void);
void memConfigure(void);
/// Allocate one element from the typed pool
void *memAllocate(mem_type);
void *memAllocString(size_t net_size, size_t * gross_size);
void *memAllocBuf(size_t net_size, size_t * gross_size);
void *memReallocBuf(void *buf, size_t net_size, size_t * gross_size);
/// Free a element allocated by memAllocate()
void memFree(void *, int type);
void memFreeString(size_t size, void *);
void memFreeBuf(size_t size, void *);
FREE *memFreeBufFunc(size_t size);
int memInUse(mem_type);
void memDataInit(mem_type, const char *, size_t, int, bool doZero = true);
void memCheckInit(void);
void memConfigure(void);

#endif /* SQUID_MEM */

