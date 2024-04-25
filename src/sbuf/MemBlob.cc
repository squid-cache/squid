/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "sbuf/MemBlob.h"
#include "sbuf/Stats.h"

#include <iostream>

InstanceIdDefinitions(MemBlob, "blob");

/* MemBlobStats */

MemBlobStats&
MemBlobStats::operator += (const MemBlobStats& s)
{
    alloc+=s.alloc;
    live+=s.live;
    append+=s.append;
    liveBytes+=s.liveBytes;

    return *this;
}

void
MemBlobStats::dump(std::ostream &yaml) const
{
    std::string indent("  ");
    yaml <<
        "MemBlob stats: " << '\n' <<
            indent << "allocations: " << alloc << '\n' <<
            indent << "live instances: " << live << '\n' <<
            indent << "append calls: " << append << '\n' <<
            indent << "cumulative size bytes: " << liveBytes << '\n' <<
            indent << "mean size: " << std::fixed << std::setprecision(1) <<
                (static_cast<double>(liveBytes)/(live?live:1)) << '\n';
}

static auto &
WriteableStats()
{
    static const auto stats = new MemBlobStats();
    return *stats;
}

const MemBlobStats &
MemBlob::GetStats()
{
    return WriteableStats();
}

/* MemBlob */

MemBlob::MemBlob(const MemBlob::size_type reserveSize) :
    mem(nullptr), capacity(0), size(0) // will be set by memAlloc
{
    debugs(MEMBLOB_DEBUGSECTION,9, "constructed, this="
           << static_cast<void*>(this) << " id=" << id
           << " reserveSize=" << reserveSize);
    memAlloc(reserveSize);
}

MemBlob::MemBlob(const char *buffer, const MemBlob::size_type bufSize) :
    mem(nullptr), capacity(0), size(0) // will be set by memAlloc
{
    debugs(MEMBLOB_DEBUGSECTION,9, "constructed, this="
           << static_cast<void*>(this) << " id=" << id
           << " buffer=" << static_cast<const void*>(buffer)
           << " bufSize=" << bufSize);
    memAlloc(bufSize);
    append(buffer, bufSize);
}

MemBlob::~MemBlob()
{
    if (mem || capacity)
        memFreeBuf(capacity, mem);
    auto &stats = WriteableStats();
    stats.liveBytes -= capacity;
    --stats.live;
    SBufStats::RecordMemBlobSizeAtDestruct(capacity);

    debugs(MEMBLOB_DEBUGSECTION,9, "destructed, this="
           << static_cast<void*>(this) << " id=" << id
           << " capacity=" << capacity
           << " size=" << size);
}

/** Allocate an available space area of at least minSize bytes in size.
 *  Must be called by constructors and only by constructors.
 */
void
MemBlob::memAlloc(const size_type minSize)
{
    size_t actualAlloc = minSize;

    Must(!mem);
    mem = static_cast<char*>(memAllocBuf(actualAlloc, &actualAlloc));
    Must(mem);

    capacity = actualAlloc;
    size = 0;
    debugs(MEMBLOB_DEBUGSECTION, 8,
           id << " memAlloc: requested=" << minSize <<
           ", received=" << capacity);
    auto &stats = WriteableStats();
    ++stats.live;
    ++stats.alloc;
    stats.liveBytes += capacity;
}

void
MemBlob::appended(const size_type n)
{
    Must(willFit(n));
    size += n;
    ++WriteableStats().append;
}

void
MemBlob::append(const char *source, const size_type n)
{
    if (n > 0) { // appending zero bytes is allowed but only affects the stats
        Must(willFit(n));
        Must(source);
        memmove(mem + size, source, n);
        size += n;
    }
    ++WriteableStats().append;
}

void
MemBlob::syncSize(const size_type n)
{
    debugs(MEMBLOB_DEBUGSECTION, 7, n << " was: " << size);
    Must(LockCount() <= 1);
    Must(n <= size);
    size = n;
}

void
MemBlob::consume(const size_type rawN)
{
    if (rawN && size) {
        Must(LockCount() <= 1);
        const auto n = std::min(rawN, size);
        size -= n;
        if (size)
            memmove(mem, mem + n, size);
    }
}

std::ostream&
MemBlob::dump(std::ostream &os) const
{
    os << "id @" << (void *)this
       << "mem:" << static_cast<void*>(mem)
       << ",capacity:" << capacity
       << ",size:" << size
       << ",refs:" << LockCount() << "; ";
    return os;
}

