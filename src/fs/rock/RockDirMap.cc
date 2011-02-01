/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"

#include "Store.h"
#include "fs/rock/RockDirMap.h"

static const char SharedMemoryName[] = "RockDirMap";

Rock::DirMap::DirMap(const char *const aPath, const int limit):
    path(aPath), shm(sharedMemoryName())
{
    shm.create(SharedSize(limit));
    assert(shm.mem());
    shared = new (shm.mem()) Shared(limit);
    debugs(79, 5, HERE << "] new map [" << path << "] created using a new "
           "shared memory segment for cache_dir '" << path << "' with limit=" <<
           entryLimit());
}

Rock::DirMap::DirMap(const char *const aPath):
    path(aPath), shm(sharedMemoryName())
{
    shm.open();
    assert(shm.mem());
    shared = reinterpret_cast<Shared *>(shm.mem());
    debugs(79, 5, HERE << "] new map [" << path << "] created using existing "
           "shared memory segment for cache_dir '" << path << "' with limit=" <<
           entryLimit());
}

StoreEntryBasics *
Rock::DirMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    debugs(79, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    const int idx = slotIdx(key);
    free(idx);
    Slot &s = shared->slots[idx];
    freeIfNeeded(s);
    if (s.state.swap_if(Slot::Empty, Slot::Writing)) {
        fileno = idx;
        s.setKey(key);
        ++shared->count;
        debugs(79, 5, HERE << " opened slot at " << fileno << " for key " <<
               storeKeyText(key) << " for writing in map [" << path << ']');
        return &s.seBasics;
    }
    debugs(79, 5, HERE << " failed to open slot for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    return 0;
}

void
Rock::DirMap::closeForWriting(const sfileno fileno)
{
    debugs(79, 5, HERE << " closing slot at " << fileno << " for writing and "
           "openning for reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state == Slot::Writing);
    ++s.readLevel;
    assert(s.state.swap_if(Slot::Writing, Slot::Usable));
}

bool
Rock::DirMap::free(const sfileno fileno)
{
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    if (s.state.swap_if(Slot::Usable, Slot::WaitingToBeFreed)) {
        debugs(79, 5, HERE << " marked slot at " << fileno << " to be freed in"
               " map [" << path << ']');
        freeIfNeeded(s);
        return true;
    }
    debugs(79, 5, HERE << " failed to mark slot at " << fileno << " to be "
           "freed in map [" << path << ']');
    return false;
}

const StoreEntryBasics *
Rock::DirMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(79, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    const int idx = slotIdx(key);
    const StoreEntryBasics *const seBasics = openForReadingAt(idx);
    if (seBasics) {
        Slot &s = shared->slots[idx];
        if (s.checkKey(key)) {
            fileno = idx;
            debugs(79, 5, HERE << " opened slot at " << fileno << " for key "
                   << storeKeyText(key) << " for reading in map [" << path <<
                   ']');
            return seBasics;
        }
        --s.readLevel;
        freeIfNeeded(s);
    }
    debugs(79, 5, HERE << " failed to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    return 0;
}

const StoreEntryBasics *
Rock::DirMap::openForReadingAt(const sfileno fileno)
{
    debugs(79, 5, HERE << " trying to open slot at " << fileno << " for "
           "reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    ++s.readLevel;
    if (s.state == Slot::Usable) {
        debugs(79, 5, HERE << " opened slot at " << fileno << " for reading in"
               " map [" << path << ']');
        return &s.seBasics;
    }
    --s.readLevel;
    freeIfNeeded(s);
    debugs(79, 5, HERE << " failed to open slot at " << fileno << " for "
           "reading in map [" << path << ']');
    return 0;
}

void
Rock::DirMap::closeForReading(const sfileno fileno)
{
    debugs(79, 5, HERE << " closing slot at " << fileno << " for reading in "
           "map [" << path << ']');
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
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(key);
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
    const int idx = &s - shared->slots;
    if (s.state.swap_if(Slot::WaitingToBeFreed, Slot::Freeing)) {
        debugs(79, 5, HERE << " trying to free slot at " << idx << " in map ["
               << path << ']');
        if (s.readLevel > 0) {
            assert(s.state.swap_if(Slot::Freeing, Slot::WaitingToBeFreed));
            debugs(79, 5, HERE << " failed to free slot at " << idx << " in "
                   "map [" << path << ']');
        } else {
            memset(s.key_, 0, sizeof(s.key_));
            memset(&s.seBasics, 0, sizeof(s.seBasics));
            --shared->count;
            assert(s.state.swap_if(Slot::Freeing, Slot::Empty));
            debugs(79, 5, HERE << " freed slot at " << idx << " in map [" <<
                   path << ']');
        }
    }
}

String
Rock::DirMap::sharedMemoryName()
{
    String result;
    const char *begin = path.termedBuf();
    for (const char *end = strchr(begin, '/'); end; end = strchr(begin, '/')) {
        if (begin != end) {
            result.append(begin, end - begin);
            result.append('.');
        }
        begin = end + 1;
    }
    result.append(begin);
    return result;
}

int
Rock::DirMap::SharedSize(const int limit)
{
    return sizeof(Shared) + limit * sizeof(Slot);
}

void
Rock::DirMap::Slot::setKey(const cache_key *const aKey)
{
    memcpy(key_, aKey, sizeof(key_));
}

bool
Rock::DirMap::Slot::checkKey(const cache_key *const aKey) const
{
    const uint32_t *const k = reinterpret_cast<const uint32_t *>(aKey);
    return k[0] == key_[0] && k[1] == key_[1] &&
           k[2] == key_[2] && k[3] == key_[3];
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
