/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 13    High Level Memory Pool Management */

#ifndef _SQUID_SRC_MEM_FORWARD_H
#define _SQUID_SRC_MEM_FORWARD_H

#include "mem/AllocatorProxy.h"

#include <iosfwd>

class StoreEntry;
class MemPoolStats;
class MemPoolMeter;

/// Memory Management
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

/// \deprecated use MEMPROXY_CLASS instead.
typedef void FREE(void *);

/// Types of memory pool which do not yet use MEMPROXY_CLASS() API
typedef enum {
    MEM_NONE,
    MEM_2K_BUF,
    MEM_4K_BUF,
    MEM_8K_BUF,
    MEM_16K_BUF,
    MEM_32K_BUF,
    MEM_64K_BUF,
    MEM_DREAD_CTRL,
    MEM_DWRITE_Q,
    MEM_MD5_DIGEST,
    MEM_MAX
} mem_type;

/// Main cleanup handler.
void memClean(void);
void memInitModule(void);
void memCleanModule(void);
void memConfigure(void);
/// Allocate one element from the typed pool
void *memAllocate(mem_type);
void *memAllocString(size_t net_size, size_t * gross_size);
void *memAllocBuf(size_t net_size, size_t * gross_size);
void *memAllocRigid(size_t net_size);
void *memReallocBuf(void *buf, size_t net_size, size_t * gross_size);
/// Free a element allocated by memAllocate()
void memFree(void *, int type);
void memFreeString(size_t size, void *);
void memFreeBuf(size_t size, void *);
void memFreeRigid(void *, size_t net_size);
FREE *memFreeBufFunc(size_t size);
int memInUse(mem_type);
void memDataInit(mem_type, const char *, size_t, int, bool doZero = true);
void memCheckInit(void);

#endif /* _SQUID_SRC_MEM_FORWARD_H */

