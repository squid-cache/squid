/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"

#include "Store.h"
#include "fs/rock/RockDirMap.h"

static const char SharedMemoryName[] = "RockDirMap";

Rock::DirMap::DirMap(const char *const path, const int limit):
    shm(SharedMemoryName(path))
{
    shm.create(limit);
    assert(shm.mem());
    shared = new (shm.mem()) Shared(limit);
}

Rock::DirMap::DirMap(const char *const path):
    shm(SharedMemoryName(path))
{
    shm.open();
    assert(shm.mem());
    shared = reinterpret_cast<Shared *>(shm.mem());
}

StoreEntryBasics *
Rock::DirMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    const int idx = slotIdx(key);
    free(idx);
    Slot &s = shared->slots[idx];
    if (s.state.swap_if(Slot::Empty, Slot::Writing)) {
        s.setKey(key);
        return &s.seBasics;
    }
    return 0;
}

void
Rock::DirMap::closeForWriting(const sfileno fileno)
{
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state == Slot::Writing);
    ++shared->count;
    assert(s.state.swap_if(Slot::Writing, Slot::Usable));
}

bool
Rock::DirMap::free(const sfileno fileno)
{
    if (openForReadingAt(fileno)) {
        Slot &s = shared->slots[fileno];
        s.state.swap_if(Slot::Usable, Slot::WaitingToBeFreed);
        --s.readLevel;
        freeIfNeeded(s);
        return true;
    }
    return false;
}

const StoreEntryBasics *
Rock::DirMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    const int idx = slotIdx(key);
    const StoreEntryBasics *const seBasics = openForReadingAt(idx);
    if (seBasics && shared->slots[idx].checkKey(key)) {
        fileno = idx;
        return seBasics;
    }
    return 0;
}

const StoreEntryBasics *
Rock::DirMap::openForReadingAt(const sfileno fileno)
{
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    ++s.readLevel;
    if (s.state == Slot::Usable)
        return &s.seBasics;
    --s.readLevel;
    freeIfNeeded(s);
    return 0;
}

void
Rock::DirMap::closeForReading(const sfileno fileno)
{
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.readLevel > 0);
    --s.readLevel;
    freeIfNeeded(s);
}

int
Rock::DirMap::entryLimit() const
{
    return shared->limit;
}

int
Rock::DirMap::entryCount() const
{
    return shared->count;
}

bool
Rock::DirMap::full() const
{
    return entryCount() >= entryLimit();
}

bool
Rock::DirMap::valid(const int pos) const
{
    return 0 <= pos && pos < entryLimit();
}

int
Rock::DirMap::AbsoluteEntryLimit()
{
    const int sfilenoMax = 0xFFFFFF; // Core sfileno maximum
    return sfilenoMax;
}

int
Rock::DirMap::slotIdx(const cache_key *const key) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(&key);
    // TODO: use a better hash function
    return (k[0] + k[1]) % shared->limit;
}

Rock::DirMap::Slot &
Rock::DirMap::slot(const cache_key *const key)
{
    return shared->slots[slotIdx(key)];
}

void
Rock::DirMap::freeIfNeeded(Slot &s)
{
    if (s.state.swap_if(Slot::WaitingToBeFreed, Slot::Freeing)) {
        if (s.readLevel > 0) {
            assert(s.state.swap_if(Slot::Freeing, Slot::WaitingToBeFreed));
        } else {
            memset(s.key, 0, sizeof(s.key));
            memset(&s.seBasics, 0, sizeof(s.seBasics));
            --shared->count;
            assert(s.state.swap_if(Slot::Freeing, Slot::Empty));
        }
    }
}

int
Rock::DirMap::SharedSize(const int limit)
{
    return sizeof(Shared) + limit * sizeof(Slot);
}

String
Rock::DirMap::SharedMemoryName(const char *path)
{
    String result;
    for (const char *p = strchr(path, '/'); p; p = strchr(path, '/')) {
        if (path != p) {
            result.append('.');
            result.append(path, p - path);
        }
        path = p + 1;
    }
    result.append(path);
    return result;
}

void
Rock::DirMap::Slot::setKey(const cache_key *const aKey)
{
    memcpy(key, aKey, sizeof(key));
}

bool
Rock::DirMap::Slot::checkKey(const cache_key *const aKey) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(&key);
    return k[0] == key[0] && k[1] == key[1];
}

Rock::DirMap::Shared::Shared(const int aLimit): limit(aLimit), count(0)
{
}

void
StoreEntryBasics::set(const StoreEntry &from)
{
    memset(this, 0, sizeof(*this));
    timestamp = from.timestamp;
    lastref = from.lastref;
    expires = from.expires;
    lastmod = from.lastmod;
    swap_file_sz = from.swap_file_sz;
    refcount = from.refcount;
    flags = from.flags;
}
