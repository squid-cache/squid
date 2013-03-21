/*
 * DEBUG: section 13    High Level Memory Pool Management
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_MEM
#define SQUID_MEM

/* for mem_type */
#include "enums.h"
/* for FREE */
#include "typedefs.h"

#if HAVE_IOSFWD
#include <iosfwd>
#endif

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
void memConfigure(void);

#endif /* SQUID_MEM */
