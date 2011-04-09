/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"

#include "Store.h"
#include "fs/rock/RockDirMap.h"

Rock::DirMap::DirMap(const char *const aPath, const int limit):
    Ipc::StoreMap(aPath, limit, Shared::MemSize(limit))
{
    assert(shm.mem());
    shared = new (shm.reserve(Shared::MemSize(limit))) Shared;
}

Rock::DirMap::DirMap(const char *const aPath):
    Ipc::StoreMap(aPath)
{
    const int limit = entryLimit();
    assert(shm.mem());
    shared = reinterpret_cast<Shared *>(shm.reserve(Shared::MemSize(limit)));
}

Rock::DbCellHeader &
Rock::DirMap::header(const sfileno fileno)
{
    assert(0 <= fileno && fileno < entryLimit());
    assert(shared);
    return shared->headers[fileno];
}

const Rock::DbCellHeader &
Rock::DirMap::header(const sfileno fileno) const
{
    assert(0 <= fileno && fileno < entryLimit());
    assert(shared);
    return shared->headers[fileno];
}

int
Rock::DirMap::AbsoluteEntryLimit()
{
    const int sfilenoMax = 0xFFFFFF; // Core sfileno maximum
    return sfilenoMax;
}

size_t
Rock::DirMap::Shared::MemSize(int limit)
{
    return sizeof(Shared) + limit*sizeof(DbCellHeader);
}
