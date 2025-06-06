/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/MemMap.h"
#include "store_key_md5.h"
#include "tools.h"

Ipc::MemMap::MemMap(const char *const aPath) :
    cleaner(nullptr),
    path(aPath),
    shared(shm_old(Shared)(aPath))
{
    assert(shared->limit > 0); // we should not be created otherwise
    debugs(54, 5, "attached map [" << path << "] created: " <<
           shared->limit);
}

Ipc::MemMap::Owner *
Ipc::MemMap::Init(const char *const path, const int limit, const size_t extrasSize)
{
    assert(limit > 0); // we should not be created otherwise
    Owner *const owner = shm_new(Shared)(path, limit, extrasSize);
    debugs(54, 5, "new map [" << path << "] created: " << limit);
    return owner;
}

Ipc::MemMap::Owner *
Ipc::MemMap::Init(const char *const path, const int limit)
{
    return Init(path, limit, 0);
}

Ipc::MemMap::Slot *
Ipc::MemMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, "trying to open slot for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    const int idx = slotIndexByKey(key);

    if (Slot *slot = openForWritingAt(idx)) {
        fileno = idx;
        return slot;
    }

    return nullptr;
}

Ipc::MemMap::Slot *
Ipc::MemMap::openForWritingAt(const sfileno fileno, bool overwriteExisting)
{
    Slot &s = shared->slots[fileno];
    ReadWriteLock &lock = s.lock;

    if (lock.lockExclusive()) {
        assert(s.writing() && !s.reading());

        // bail if we cannot empty this position
        if (!s.waitingToBeFreed && !s.empty() && !overwriteExisting) {
            lock.unlockExclusive();
            debugs(54, 5, "cannot open existing entry " << fileno <<
                   " for writing " << path);
            return nullptr;
        }

        // free if the entry was used, keeping the entry locked
        if (s.waitingToBeFreed || !s.empty())
            freeLocked(s, true);

        assert(s.empty());
        ++shared->count;

        debugs(54, 5, "opened slot at " << fileno <<
               " for writing in map [" << path << ']');
        return &s; // and keep the entry locked
    }

    debugs(54, 5, "failed to open slot at " << fileno <<
           " for writing in map [" << path << ']');
    return nullptr;
}

void
Ipc::MemMap::closeForWriting(const sfileno fileno)
{
    debugs(54, 5, "stop writing slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.writing());
    s.lock.unlockExclusive();
}

void
Ipc::MemMap::switchWritingToReading(const sfileno fileno)
{
    debugs(54, 5, "switching writing slot at " << fileno <<
           " to reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.writing());
    s.lock.switchExclusiveToShared();
}

/// terminate writing the entry, freeing its slot for others to use
void
Ipc::MemMap::abortWriting(const sfileno fileno)
{
    debugs(54, 5, "abort writing slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.writing());
    freeLocked(s, false);
}

const Ipc::MemMap::Slot *
Ipc::MemMap::peekAtReader(const sfileno fileno) const
{
    assert(valid(fileno));
    const Slot &s = shared->slots[fileno];
    if (s.reading())
        return &s; // immediate access by lock holder so no locking
    if (s.writing())
        return nullptr; // cannot read the slot when it is being written
    assert(false); // must be locked for reading or writing
    return nullptr;
}

void
Ipc::MemMap::free(const sfileno fileno)
{
    debugs(54, 5, "marking slot at " << fileno << " to be freed in"
           " map [" << path << ']');

    assert(valid(fileno));
    Slot &s = shared->slots[fileno];

    if (s.lock.lockExclusive())
        freeLocked(s, false);
    else
        s.waitingToBeFreed = true; // mark to free it later
}

const Ipc::MemMap::Slot *
Ipc::MemMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, "trying to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    const int idx = slotIndexByKey(key);
    if (const Slot *slot = openForReadingAt(idx)) {
        if (slot->sameKey(key)) {
            fileno = idx;
            debugs(54, 5, "opened slot at " << fileno << " for key "
                   << storeKeyText(key) << " for reading in map [" << path <<
                   ']');
            return slot; // locked for reading
        }
        slot->lock.unlockShared();
    }
    debugs(54, 5, "failed to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    return nullptr;
}

const Ipc::MemMap::Slot *
Ipc::MemMap::openForReadingAt(const sfileno fileno)
{
    debugs(54, 5, "trying to open slot at " << fileno << " for "
           "reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];

    if (!s.lock.lockShared()) {
        debugs(54, 5, "failed to lock slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return nullptr;
    }

    if (s.empty()) {
        s.lock.unlockShared();
        debugs(54, 7, "empty slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return nullptr;
    }

    if (s.waitingToBeFreed) {
        s.lock.unlockShared();
        debugs(54, 7, "dirty slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return nullptr;
    }

    debugs(54, 5, "opened slot at " << fileno << " for reading in"
           " map [" << path << ']');
    return &s;
}

void
Ipc::MemMap::closeForReading(const sfileno fileno)
{
    debugs(54, 5, "closing slot at " << fileno << " for reading in "
           "map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.reading());
    s.lock.unlockShared();
}

int
Ipc::MemMap::entryLimit() const
{
    return shared->limit;
}

int
Ipc::MemMap::entryCount() const
{
    return shared->count;
}

bool
Ipc::MemMap::full() const
{
    return entryCount() >= entryLimit();
}

void
Ipc::MemMap::updateStats(ReadWriteLockStats &stats) const
{
    for (int i = 0; i < shared->limit; ++i)
        shared->slots[i].lock.updateStats(stats);
}

bool
Ipc::MemMap::valid(const int pos) const
{
    return 0 <= pos && pos < entryLimit();
}

static
unsigned int
hash_key(const unsigned char *data, unsigned int len, unsigned int hashSize)
{
    unsigned int n;
    unsigned int j;
    for (j = 0, n = 0; j < len; j++ ) {
        n ^= 271 * *data;
        ++data;
    }
    return (n ^ (j * 271)) % hashSize;
}

int
Ipc::MemMap::slotIndexByKey(const cache_key *const key) const
{
    const unsigned char *k = reinterpret_cast<const unsigned char *>(key);
    return hash_key(k, MEMMAP_SLOT_KEY_SIZE, shared->limit);
}

Ipc::MemMap::Slot &
Ipc::MemMap::slotByKey(const cache_key *const key)
{
    return shared->slots[slotIndexByKey(key)];
}

/// unconditionally frees the already exclusively locked slot and releases lock
void
Ipc::MemMap::freeLocked(Slot &s, bool keepLocked)
{
    if (!s.empty() && cleaner)
        cleaner->noteFreeMapSlot(&s - shared->slots.raw());

    s.waitingToBeFreed = false;
    memset(s.key, 0, sizeof(s.key));
    if (!keepLocked)
        s.lock.unlockExclusive();
    --shared->count;
    debugs(54, 5, "freed slot at " << (&s - shared->slots.raw()) <<
           " in map [" << path << ']');
}

/* Ipc::MemMapSlot */
Ipc::MemMapSlot::MemMapSlot() :
    pSize(0),
    expire(0)
{
    memset(key, 0, sizeof(key));
    memset(p, 0, sizeof(p));
}

void
Ipc::MemMapSlot::set(const unsigned char *aKey, const void *block, size_t blockSize, time_t expireAt)
{
    memcpy(key, aKey, sizeof(key));
    if (block)
        memcpy(p, block, blockSize);
    pSize = blockSize;
    expire = expireAt;
}

bool
Ipc::MemMapSlot::sameKey(const cache_key *const aKey) const
{
    return (memcmp(key, aKey, sizeof(key)) == 0);
}

bool
Ipc::MemMapSlot::empty() const
{
    for (unsigned char const*u = key; u < key + sizeof(key); ++u) {
        if (*u)
            return false;
    }
    return true;
}

/* Ipc::MemMap::Shared */

Ipc::MemMap::Shared::Shared(const int aLimit, const size_t anExtrasSize):
    limit(aLimit), extrasSize(anExtrasSize), count(0), slots(aLimit)
{
}

Ipc::MemMap::Shared::~Shared()
{
}

size_t
Ipc::MemMap::Shared::sharedMemorySize() const
{
    return SharedMemorySize(limit, extrasSize);
}

size_t
Ipc::MemMap::Shared::SharedMemorySize(const int limit, const size_t extrasSize)
{
    return sizeof(Shared) + limit * (sizeof(Slot) + extrasSize);
}

