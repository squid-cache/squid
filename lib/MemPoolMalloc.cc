
/*
 * $Id$
 *
 * DEBUG: section 63    Low Level Memory Pool Management
 * AUTHOR: Alex Rousskov, Andres Kroonmaa, Robert Collins, Henrik Nordstrom
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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


#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "MemPoolMalloc.h"

#if HAVE_STRING_H
#include <string.h>
#endif

/*
 * XXX This is a boundary violation between lib and src.. would be good
 * if it could be solved otherwise, but left for now.
 */
extern time_t squid_curtime;

void *
MemPoolMalloc::allocate()
{
    void *obj = freelist.pop();
    if (obj) {
        memMeterDec(meter.idle);
        saved_calls++;
    } else {
        obj = xcalloc(1, obj_size);
        memMeterInc(meter.alloc);
    }
    memMeterInc(meter.inuse);
    return obj;
}

void
MemPoolMalloc::deallocate(void *obj, bool aggressive)
{
    memMeterDec(meter.inuse);
    if (aggressive) {
        xfree(obj);
        memMeterDec(meter.alloc);
    } else {
        if (doZeroOnPush)
            memset(obj, 0, obj_size);
        memMeterInc(meter.idle);
        freelist.push_back(obj);
    }
}

/* TODO extract common logic to MemAllocate */
int
MemPoolMalloc::getStats(MemPoolStats * stats, int accumulate)
{
    if (!accumulate)	/* need skip memset for GlobalStats accumulation */
        memset(stats, 0, sizeof(MemPoolStats));

    stats->pool = this;
    stats->label = objectType();
    stats->meter = &meter;
    stats->obj_size = obj_size;
    stats->chunk_capacity = 0;

    stats->chunks_alloc += 0;
    stats->chunks_inuse += 0;
    stats->chunks_partial += 0;
    stats->chunks_free += 0;

    stats->items_alloc += meter.alloc.level;
    stats->items_inuse += meter.inuse.level;
    stats->items_idle += meter.idle.level;

    stats->overhead += sizeof(MemPoolMalloc) + strlen(objectType()) + 1;

    return meter.inuse.level;
}

int
MemPoolMalloc::getInUseCount()
{
    return meter.inuse.level;
}

MemPoolMalloc::MemPoolMalloc(char const *aLabel, size_t aSize) : MemImplementingAllocator(aLabel, aSize)
{
}

MemPoolMalloc::~MemPoolMalloc()
{
    assert(meter.inuse.level == 0);
    clean(0);
}

bool
MemPoolMalloc::idleTrigger(int shift) const
{
    return freelist.count >> (shift ? 8 : 0);
}

void
MemPoolMalloc::clean(time_t maxage)
{
    while (void *obj = freelist.pop()) {
        memMeterDec(meter.idle);
        memMeterDec(meter.alloc);
        xfree(obj);
    }
}

