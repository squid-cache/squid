/*
 * $Id$
 *
 * DEBUG: section 20    Memory Cache
 */

#include "config.h"

#include "Store.h"
#include "MemStoreMap.h"

MemStoreMap::MemStoreMap(const char *const aPath, const int limit):
    Ipc::StoreMap(aPath, limit, Shared::MemSize(limit))
{
    assert(shm.mem());
    shared = new (shm.reserve(Shared::MemSize(limit))) Shared;
}

MemStoreMap::MemStoreMap(const char *const aPath):
    Ipc::StoreMap(aPath)
{
    const int limit = entryLimit();
    assert(shm.mem());
    shared = reinterpret_cast<Shared *>(shm.reserve(Shared::MemSize(limit)));
}

MemStoreMap::Extras &
MemStoreMap::extras(const sfileno fileno)
{
    assert(0 <= fileno && fileno < entryLimit());
    assert(shared);
    return shared->extras[fileno];
}

const MemStoreMap::Extras &
MemStoreMap::extras(const sfileno fileno) const
{
    assert(0 <= fileno && fileno < entryLimit());
    assert(shared);
    return shared->extras[fileno];
}

size_t
MemStoreMap::Shared::MemSize(int limit)
{
    return sizeof(Shared) + limit*sizeof(Extras);
}
