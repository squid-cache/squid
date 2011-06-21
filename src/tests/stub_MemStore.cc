/*
 * $Id$
 *
 * DEBUG: section 84    Helper process maintenance
 *
 */

#include "config.h"
#include "MemStore.h"

#define STUB_API "MemStore.cc"
#include "tests/STUB.h"

MemStore::MemStore() STUB
MemStore::~MemStore() STUB
void MemStore::considerKeeping(StoreEntry &) STUB
void MemStore::reference(StoreEntry &) STUB
void MemStore::maintain() STUB
void MemStore::cleanReadable(const sfileno) STUB
void MemStore::get(String const, STOREGETCLIENT, void *) STUB
void MemStore::init() STUB
void MemStore::stat(StoreEntry &) const STUB

int MemStore::callback()
{
    STUB
    return 0;
}

StoreEntry *MemStore::get(const cache_key *)
{
    STUB
    return NULL;
}

uint64_t MemStore::maxSize() const
{
    STUB
    return 0;
}

uint64_t MemStore::minSize() const
{
    STUB
    return 0;
}

uint64_t MemStore::currentSize() const
{
    STUB
    return 0;
}

uint64_t MemStore::currentCount() const
{
    STUB
    return 0;
}

int64_t MemStore::maxObjectSize() const
{
    STUB
    return 0;
}

StoreSearch *MemStore::search(String const, HttpRequest *)
{
    STUB
    return NULL;
}

bool MemStore::dereference(StoreEntry &)
{
    STUB
    return false;
}
