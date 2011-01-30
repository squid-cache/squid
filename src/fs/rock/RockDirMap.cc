/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "fs/rock/RockDirMap.h"

static const char SharedMemoryName[] = "RockDirMap";

Rock::DirMap::DirMap(const int id, const int limit):
    shm(SharedMemoryName, id)
{
    shm.create(limit);
    assert(shm.mem());
    shared = new (shm.mem()) Shared(limit);
}

Rock::DirMap::DirMap(const int id):
    shm(SharedMemoryName, id)
{
    shm.open();
    assert(shm.mem());
    shared = reinterpret_cast<Shared *>(shm.mem());
}

bool
Rock::DirMap::initialize(const cache_key *const key, const StoreEntryBasics &seBasics)
{
    Slot &s = slot(key);
    if (s.state.swap_if(Slot::WaitingToBeInitialized, Slot::Initializing)) {
        s.setKey(key);
        s.seBasics = seBasics;
        ++shared->count;
        assert(s.state.swap_if(Slot::Initializing, Slot::Usable));
        return true;
    }
    return false;
}

bool
Rock::DirMap::initialize(const int idx)
{
    return valid(idx) &&
        shared->slots[idx].state.swap_if(Slot::WaitingToBeInitialized, Slot::Empty);
}

StoreEntryBasics *
Rock::DirMap::add(const cache_key *const key)
{
    Slot &s = slot(key);
    if (s.state.swap_if(Slot::Empty, Slot::Writing)) {
        s.setKey(key);
        return &s.seBasics;
    }
    return 0;
}

void
Rock::DirMap::added(const cache_key *const key)
{
    Slot &s = slot(key);
    assert(s.checkKey(key));
    assert(s.state == Slot::Writing);
    ++shared->count;
    assert(s.state.swap_if(Slot::Writing, Slot::Usable));
}

bool
Rock::DirMap::free(const cache_key *const key)
{
    int idx;
    if (open(key, idx)) {
        Slot &s = shared->slots[idx];
        s.state.swap_if(Slot::Usable, Slot::WaitingToBeFreed);
        --s.readLevel;
        freeIfNeeded(s);
    }
    return false;
}

const StoreEntryBasics *
Rock::DirMap::open(const cache_key *const key, sfileno &fileno)
{
    const int idx = slotIdx(key);
    Slot &s = shared->slots[idx];
    ++s.readLevel;
    if (s.state == Slot::Usable && s.checkKey(key)) {
        fileno = idx;
        return &s.seBasics;
    }
    --s.readLevel;
    freeIfNeeded(s);
    return 0;
}

void
Rock::DirMap::close(const cache_key *const key)
{
    Slot &s = slot(key);
    assert(s.checkKey(key));
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
            s.state.swap_if(Slot::Freeing, Slot::Empty);
        }
    }
}

int
Rock::DirMap::SharedSize(const int limit)
{
    return sizeof(Shared) + limit * sizeof(Slot);
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
