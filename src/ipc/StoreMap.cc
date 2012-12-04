/*
 * DEBUG: section 54    Interprocess Communication
 */

#include "squid.h"
#include "ipc/StoreMap.h"
#include "store_key_md5.h"
#include "Store.h"
#include "tools.h"

Ipc::StoreMap::Owner *
Ipc::StoreMap::Init(const char *const path, const int limit, const size_t extrasSize)
{
    assert(limit > 0); // we should not be created otherwise
    Owner *const owner = shm_new(Shared)(path, limit, extrasSize);
    debugs(54, 5, HERE << "new map [" << path << "] created: " << limit);
    return owner;
}

Ipc::StoreMap::Owner *
Ipc::StoreMap::Init(const char *const path, const int limit)
{
    return Init(path, limit, 0);
}

Ipc::StoreMap::StoreMap(const char *const aPath): cleaner(NULL), path(aPath),
        shared(shm_old(Shared)(aPath))
{
    assert(shared->limit > 0); // we should not be created otherwise
    debugs(54, 5, HERE << "attached map [" << path << "] created: " <<
           shared->limit);
}

Ipc::StoreMap::Slot *
Ipc::StoreMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    const int idx = slotIndexByKey(key);

    Slot &s = shared->slots[idx];
    ReadWriteLock &lock = s.lock;

    if (lock.lockExclusive()) {
        assert(s.state != Slot::Writeable); // until we start breaking locks

        // free if the entry was used, keeping the entry locked
        if (s.waitingToBeFreed || s.state == Slot::Readable)
            freeLocked(s, true);

        assert(s.state == Slot::Empty);
        ++shared->count;
        s.state = Slot::Writeable;
        fileno = idx;
        //s.setKey(key); // XXX: the caller should do that
        debugs(54, 5, HERE << " opened slot at " << idx <<
               " for writing in map [" << path << ']');
        return &s; // and keep the entry locked
    }

    debugs(54, 5, HERE << " failed to open slot at " << idx <<
           " for writing in map [" << path << ']');
    return NULL;
}

void
Ipc::StoreMap::closeForWriting(const sfileno fileno, bool lockForReading)
{
    debugs(54, 5, HERE << " closing slot at " << fileno << " for writing and "
           "openning for reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state == Slot::Writeable);
    s.state = Slot::Readable;
    if (lockForReading)
        s.lock.switchExclusiveToShared();
    else
        s.lock.unlockExclusive();
}

/// terminate writing the entry, freeing its slot for others to use
void
Ipc::StoreMap::abortWriting(const sfileno fileno)
{
    debugs(54, 5, HERE << " abort writing slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state == Slot::Writeable);
    freeLocked(s, false);
}

void
Ipc::StoreMap::abortIo(const sfileno fileno)
{
    debugs(54, 5, HERE << " abort I/O for slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];

    // The caller is a lock holder. Thus, if we are Writeable, then the
    // caller must be the writer; otherwise the caller must be the reader.
    if (s.state == Slot::Writeable)
        abortWriting(fileno);
    else
        closeForReading(fileno);
}

const Ipc::StoreMap::Slot *
Ipc::StoreMap::peekAtReader(const sfileno fileno) const
{
    assert(valid(fileno));
    const Slot &s = shared->slots[fileno];
    switch (s.state) {
    case Slot::Readable:
        return &s; // immediate access by lock holder so no locking
    case Slot::Writeable:
        return NULL; // cannot read the slot when it is being written
    case Slot::Empty:
        assert(false); // must be locked for reading or writing
    }
    assert(false); // not reachable
    return NULL;
}

void
Ipc::StoreMap::free(const sfileno fileno)
{
    debugs(54, 5, HERE << " marking slot at " << fileno << " to be freed in"
           " map [" << path << ']');

    assert(valid(fileno));
    Slot &s = shared->slots[fileno];

    if (s.lock.lockExclusive())
        freeLocked(s, false);
    else
        s.waitingToBeFreed = true; // mark to free it later
}

const Ipc::StoreMap::Slot *
Ipc::StoreMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    const int idx = slotIndexByKey(key);
    if (const Slot *slot = openForReadingAt(idx)) {
        if (slot->sameKey(key)) {
            fileno = idx;
            debugs(54, 5, HERE << " opened slot at " << fileno << " for key "
                   << storeKeyText(key) << " for reading in map [" << path <<
                   ']');
            return slot; // locked for reading
        }
        slot->lock.unlockShared();
    }
    debugs(54, 5, HERE << " failed to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    return NULL;
}

const Ipc::StoreMap::Slot *
Ipc::StoreMap::openForReadingAt(const sfileno fileno)
{
    debugs(54, 5, HERE << " trying to open slot at " << fileno << " for "
           "reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];

    if (!s.lock.lockShared()) {
        debugs(54, 5, HERE << " failed to lock slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return NULL;
    }

    if (s.state == Slot::Empty) {
        s.lock.unlockShared();
        debugs(54, 7, HERE << " empty slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return NULL;
    }

    if (s.waitingToBeFreed) {
        s.lock.unlockShared();
        debugs(54, 7, HERE << " dirty slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return NULL;
    }

    // cannot be Writing here if we got shared lock and checked Empty above
    assert(s.state == Slot::Readable);
    debugs(54, 5, HERE << " opened slot at " << fileno << " for reading in"
           " map [" << path << ']');
    return &s;
}

void
Ipc::StoreMap::closeForReading(const sfileno fileno)
{
    debugs(54, 5, HERE << " closing slot at " << fileno << " for reading in "
           "map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state == Slot::Readable);
    s.lock.unlockShared();
}

int
Ipc::StoreMap::entryLimit() const
{
    return shared->limit;
}

int
Ipc::StoreMap::entryCount() const
{
    return shared->count;
}

bool
Ipc::StoreMap::full() const
{
    return entryCount() >= entryLimit();
}

void
Ipc::StoreMap::updateStats(ReadWriteLockStats &stats) const
{
    for (int i = 0; i < shared->limit; ++i)
        shared->slots[i].lock.updateStats(stats);
}

bool
Ipc::StoreMap::valid(const int pos) const
{
    return 0 <= pos && pos < entryLimit();
}

int
Ipc::StoreMap::slotIndexByKey(const cache_key *const key) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(key);
    // TODO: use a better hash function
    return (k[0] + k[1]) % shared->limit;
}

Ipc::StoreMap::Slot &
Ipc::StoreMap::slotByKey(const cache_key *const key)
{
    return shared->slots[slotIndexByKey(key)];
}

/// unconditionally frees the already exclusively locked slot and releases lock
void
Ipc::StoreMap::freeLocked(Slot &s, bool keepLocked)
{
    if (s.state == Slot::Readable && cleaner)
        cleaner->cleanReadable(&s - shared->slots.raw());

    s.waitingToBeFreed = false;
    s.state = Slot::Empty;
    if (!keepLocked)
        s.lock.unlockExclusive();
    --shared->count;
    debugs(54, 5, HERE << " freed slot at " << (&s - shared->slots.raw()) <<
           " in map [" << path << ']');
}

/* Ipc::StoreMapSlot */

Ipc::StoreMapSlot::StoreMapSlot(): state(Empty)
{
    memset(&key, 0, sizeof(key));
    memset(&basics, 0, sizeof(basics));
}

void
Ipc::StoreMapSlot::setKey(const cache_key *const aKey)
{
    memcpy(key, aKey, sizeof(key));
}

bool
Ipc::StoreMapSlot::sameKey(const cache_key *const aKey) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(aKey);
    return k[0] == key[0] && k[1] == key[1];
}

void
Ipc::StoreMapSlot::set(const StoreEntry &from)
{
    memcpy(key, from.key, sizeof(key));
    // XXX: header = aHeader;
    basics.timestamp = from.timestamp;
    basics.lastref = from.lastref;
    basics.expires = from.expires;
    basics.lastmod = from.lastmod;
    basics.swap_file_sz = from.swap_file_sz;
    basics.refcount = from.refcount;
    basics.flags = from.flags;
}

/* Ipc::StoreMap::Shared */

Ipc::StoreMap::Shared::Shared(const int aLimit, const size_t anExtrasSize):
        limit(aLimit), extrasSize(anExtrasSize), count(0), slots(aLimit)
{
}

size_t
Ipc::StoreMap::Shared::sharedMemorySize() const
{
    return SharedMemorySize(limit, extrasSize);
}

size_t
Ipc::StoreMap::Shared::SharedMemorySize(const int limit, const size_t extrasSize)
{
    return sizeof(Shared) + limit * (sizeof(Slot) + extrasSize);
}

