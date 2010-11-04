/*
 * MemBlob.cc (C) 2009 Francesco Chemolli <kinkie@squid-cache.org>
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
 */


#include "config.h"
#include "base/TextException.h"
#include "Debug.h"
#include "MemBlob.h"
#if HAVE_IOSTREAM
#include <iostream>
#endif

#define MEMBLOB_USES_MEM_POOLS 0

#if MEMBLOB_USES_MEM_POOLS
#include "protos.h"
#endif

MemBlobStats MemBlob::Stats;
InstanceIdDefinitions(MemBlob, "blob");


/* MemBlobStats */

MemBlobStats::MemBlobStats(): alloc(0), live(0), append(0)
{}

std::ostream&
MemBlobStats::dump(std::ostream &os) const
{
    os <<
    "MemBlob created: " << alloc <<
    "\nMemBlob alive: " << live <<
    "\nMemBlob append calls: " << append <<
    "\nMemBlob currently allocated size: " << liveBytes <<
    "\nlive MemBlob mean current allocation size: " <<
    (static_cast<double>(liveBytes)/(live?live:1)) << std::endl;
    return os;
}


/* MemBlob */

MemBlob::MemBlob(const MemBlob::size_type reserveSize) :
        mem(NULL), capacity(0), size(0) // will be set by memAlloc
{
    debugs(MEMBLOB_DEBUGSECTION,9, HERE << "constructed, this="
           << static_cast<void*>(this) << " id=" << id
           << " reserveSize=" << reserveSize);
    memAlloc(reserveSize);
}

MemBlob::MemBlob(const char *buffer, const MemBlob::size_type bufSize) :
        mem(NULL), capacity(0), size(0) // will be set by memAlloc
{
    debugs(MEMBLOB_DEBUGSECTION,9, HERE << "constructed, this="
           << static_cast<void*>(this) << " id=" << id
           << " buffer=" << static_cast<const void*>(buffer)
           << " bufSize=" << bufSize);
    memAlloc(bufSize);
    append(buffer, bufSize);
}

MemBlob::~MemBlob()
{
#if MEMBLOB_USES_MEM_POOLS
    //no mempools for now
    // \todo reinstate mempools use
    memFreeString(capacity,mem);
#else
    xfree(mem);
#endif
    Stats.liveBytes -= capacity;
    --Stats.live;

    debugs(MEMBLOB_DEBUGSECTION,9, HERE << "destructed, this="
           << static_cast<void*>(this) << " id=" << id
           << " capacity=" << capacity
           << " size=" << size);
}

/**
 * Given the requested minimum size, return a rounded allocation size
 * for the backing store.
 * This is a stopgap call, this job is eventually expected to be handled
 * by MemPools via memAllocString.
 */
MemBlob::size_type
MemBlob::calcAllocSize(const size_type size) const
{
    if (size <= 36) return 36;
    if (size <= 128) return 128;
    if (size <= 512) return 512;
    if (size <= 4096) return RoundTo(size, 512);
    // XXX: recover squidSystemPageSize functionality. It's easy for
    //      the main squid, harder for tests
#if 0
    return RoundTo(size, squidSystemPageSize);
#else
    return RoundTo(size, 4096);
#endif
}

/** Allocate an available space area of at least minSize bytes in size.
 *  Must be called by constructors and only by constructors.
 */
void
MemBlob::memAlloc(const size_type minSize)
{
    size_t actualAlloc = calcAllocSize(minSize);

    Must(!mem);
#if MEMBLOB_USES_MEM_POOLS
    // XXX: for now, do without mempools. In order to do it, MemPools
    //  need to be singletons so that initialization order can be enforced
    mem = static_cast<char*>(memAllocString(minSize, &actualAlloc));
#else
    // \todo reinstate mempools use
    mem = static_cast<char*>(xmalloc(actualAlloc));
#endif
    Must(mem);

    capacity = actualAlloc;
    size = 0;
    debugs(MEMBLOB_DEBUGSECTION, 8,
           id << " memAlloc: requested=" << minSize <<
           ", received=" << capacity);
    ++Stats.live;
    ++Stats.alloc;
    Stats.liveBytes += capacity;
}

void
MemBlob::append(const char *source, const size_type n)
{
    if (n > 0) { // appending zero bytes is allowed but only affects the stats
        Must(willFit(n));
        Must(source);
        /// \note memcpy() is safe because we copy to an unused area
        memcpy(mem + size, source, n);
        size += n;
    }
    ++Stats.append;
}


const MemBlobStats&
MemBlob::GetStats()
{
    return Stats;
}

std::ostream&
MemBlob::dump(std::ostream &os) const
{
    os << "id @" << (void *)this
    << "mem:" << static_cast<void*>(mem)
    << ",capacity:" << capacity
    << ",size:" << size
    << ",refs:" << RefCountCount() << "; ";
    return os;
}
