/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 13    High Level Memory Pool Management */

#ifndef SQUID_SRC_MEM_FORWARD_H
#define SQUID_SRC_MEM_FORWARD_H

#include "mem/AllocatorProxy.h"

#include <iosfwd>

class StoreEntry;

/// Memory Management
namespace Mem
{
class Meter;
class PoolMeter;
class PoolStats;

void Init();
void Stats(StoreEntry *);
void CleanIdlePools(void *unused);
void Report(std::ostream &);
void PoolReport(const PoolStats *, const PoolMeter *, std::ostream &);
};

extern const size_t squidSystemPageSize;

/// \deprecated use MEMPROXY_CLASS instead.
typedef void FREE(void *);

/// Types of memory pool which do not yet use MEMPROXY_CLASS() API
typedef enum {
    MEM_NONE,
    MEM_32B_BUF,
    MEM_64B_BUF,
    MEM_128B_BUF,
    MEM_256B_BUF,
    MEM_512B_BUF,
    MEM_1K_BUF,
    MEM_2K_BUF,
    MEM_4K_BUF,
    MEM_8K_BUF,
    MEM_16K_BUF,
    MEM_32K_BUF,
    MEM_64K_BUF,
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
void *memAllocBuf(size_t net_size, size_t * gross_size);
void *memReallocBuf(void *buf, size_t net_size, size_t * gross_size);
/// Free a element allocated by memAllocate()
void memFree(void *, int type);
void memFreeBuf(size_t size, void *);
FREE *memFreeBufFunc(size_t size);
int memInUse(mem_type);

#endif /* SQUID_SRC_MEM_FORWARD_H */

