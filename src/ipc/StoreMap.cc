/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/StoreMap.h"
#include "SBuf.h"
#include "Store.h"
#include "store_key_md5.h"
#include "tools.h"

static SBuf
StoreMapSlicesId(const SBuf &path)
{
    return Ipc::Mem::Segment::Name(path, "slices");
}

static SBuf
StoreMapAnchorsId(const SBuf &path)
{
    return Ipc::Mem::Segment::Name(path, "anchors");
}

Ipc::StoreMap::Owner *
Ipc::StoreMap::Init(const SBuf &path, const int sliceLimit)
{
    assert(sliceLimit > 0); // we should not be created otherwise
    const int anchorLimit = min(sliceLimit, static_cast<int>(SwapFilenMax));
    Owner *owner = new Owner;
    owner->anchors = shm_new(Anchors)(StoreMapAnchorsId(path).c_str(), anchorLimit);
    owner->slices = shm_new(Slices)(StoreMapSlicesId(path).c_str(), sliceLimit);
    debugs(54, 5, "created " << path << " with " << anchorLimit << '+' << sliceLimit);
    return owner;
}

Ipc::StoreMap::StoreMap(const SBuf &aPath): cleaner(NULL), path(aPath),
    anchors(shm_old(Anchors)(StoreMapAnchorsId(path).c_str())),
    slices(shm_old(Slices)(StoreMapSlicesId(path).c_str()))
{
    debugs(54, 5, "attached " << path << " with " <<
           anchors->capacity << '+' << slices->capacity);
    assert(entryLimit() > 0); // key-to-position mapping requires this
    assert(entryLimit() <= sliceLimit()); // at least one slice per entry
}

int
Ipc::StoreMap::compareVersions(const sfileno fileno, time_t newVersion) const
{
    const Anchor &inode = anchorAt(fileno);

    // note: we do not lock, so comparison may be inacurate

    if (inode.empty())
        return +2;

    if (const time_t diff = newVersion - inode.basics.timestamp)
        return diff < 0 ? -1 : +1;

    return 0;
}

void
Ipc::StoreMap::forgetWritingEntry(sfileno fileno)
{
    Anchor &inode = anchorAt(fileno);

    assert(inode.writing());

    // we do not iterate slices because we were told to forget about
    // them; the caller is responsible for freeing them (most likely
    // our slice list is incomplete or has holes)

    inode.waitingToBeFreed = false;
    inode.rewind();

    inode.lock.unlockExclusive();
    --anchors->count;

    debugs(54, 8, "closed entry " << fileno << " for writing " << path);
}

Ipc::StoreMap::Anchor *
Ipc::StoreMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, "opening entry with key " << storeKeyText(key)
           << " for writing " << path);
    const int idx = anchorIndexByKey(key);

    if (Anchor *anchor = openForWritingAt(idx)) {
        fileno = idx;
        return anchor;
    }

    return NULL;
}

Ipc::StoreMap::Anchor *
Ipc::StoreMap::openForWritingAt(const sfileno fileno, bool overwriteExisting)
{
    Anchor &s = anchorAt(fileno);
    ReadWriteLock &lock = s.lock;

    if (lock.lockExclusive()) {
        assert(s.writing() && !s.reading());

        // bail if we cannot empty this position
        if (!s.waitingToBeFreed && !s.empty() && !overwriteExisting) {
            lock.unlockExclusive();
            debugs(54, 5, "cannot open existing entry " << fileno <<
                   " for writing " << path);
            return NULL;
        }

        // free if the entry was used, keeping the entry locked
        if (s.waitingToBeFreed || !s.empty())
            freeChain(fileno, s, true);

        assert(s.empty());
        s.start = -1; // we have not allocated any slices yet
        ++anchors->count;

        //s.setKey(key); // XXX: the caller should do that
        debugs(54, 5, "opened entry " << fileno << " for writing " << path);
        return &s; // and keep the entry locked
    }

    debugs(54, 5, "cannot open busy entry " << fileno <<
           " for writing " << path);
    return NULL;
}

void
Ipc::StoreMap::startAppending(const sfileno fileno)
{
    Anchor &s = anchorAt(fileno);
    assert(s.writing());
    s.lock.startAppending();
    debugs(54, 5, "restricted entry " << fileno << " to appending " << path);
}

void
Ipc::StoreMap::closeForWriting(const sfileno fileno, bool lockForReading)
{
    Anchor &s = anchorAt(fileno);
    assert(s.writing());
    if (lockForReading) {
        s.lock.switchExclusiveToShared();
        debugs(54, 5, "switched entry " << fileno <<
               " from writing to reading " << path);
        assert(s.complete());
    } else {
        s.lock.unlockExclusive();
        debugs(54, 5, "closed entry " << fileno << " for writing " << path);
        // cannot assert completeness here because we have no lock
    }
}

Ipc::StoreMap::Slice &
Ipc::StoreMap::writeableSlice(const AnchorId anchorId, const SliceId sliceId)
{
    assert(anchorAt(anchorId).writing());
    assert(validSlice(sliceId));
    return sliceAt(sliceId);
}

const Ipc::StoreMap::Slice &
Ipc::StoreMap::readableSlice(const AnchorId anchorId, const SliceId sliceId) const
{
    assert(anchorAt(anchorId).reading());
    assert(validSlice(sliceId));
    return sliceAt(sliceId);
}

Ipc::StoreMap::Anchor &
Ipc::StoreMap::writeableEntry(const AnchorId anchorId)
{
    assert(anchorAt(anchorId).writing());
    return anchorAt(anchorId);
}

const Ipc::StoreMap::Anchor &
Ipc::StoreMap::readableEntry(const AnchorId anchorId) const
{
    assert(anchorAt(anchorId).reading());
    return anchorAt(anchorId);
}

void
Ipc::StoreMap::abortWriting(const sfileno fileno)
{
    debugs(54, 5, "aborting entry " << fileno << " for writing " << path);
    Anchor &s = anchorAt(fileno);
    assert(s.writing());
    s.lock.appending = false; // locks out any new readers
    if (!s.lock.readers) {
        freeChain(fileno, s, false);
        debugs(54, 5, "closed clean entry " << fileno << " for writing " << path);
    } else {
        s.waitingToBeFreed = true;
        s.lock.unlockExclusive();
        debugs(54, 5, "closed dirty entry " << fileno << " for writing " << path);
    }
}

const Ipc::StoreMap::Anchor *
Ipc::StoreMap::peekAtReader(const sfileno fileno) const
{
    const Anchor &s = anchorAt(fileno);
    if (s.reading())
        return &s; // immediate access by lock holder so no locking
    if (s.writing())
        return NULL; // the caller is not a read lock holder
    assert(false); // must be locked for reading or writing
    return NULL;
}

const Ipc::StoreMap::Anchor &
Ipc::StoreMap::peekAtEntry(const sfileno fileno) const
{
    return anchorAt(fileno);
}

void
Ipc::StoreMap::freeEntry(const sfileno fileno)
{
    debugs(54, 5, "marking entry " << fileno << " to be freed in " << path);

    Anchor &s = anchorAt(fileno);

    if (s.lock.lockExclusive())
        freeChain(fileno, s, false);
    else
        s.waitingToBeFreed = true; // mark to free it later
}

void
Ipc::StoreMap::freeEntryByKey(const cache_key *const key)
{
    debugs(54, 5, "marking entry with key " << storeKeyText(key)
           << " to be freed in " << path);

    const int idx = anchorIndexByKey(key);
    Anchor &s = anchorAt(idx);
    if (s.lock.lockExclusive()) {
        if (s.sameKey(key))
            freeChain(idx, s, true);
        s.lock.unlockExclusive();
    } else if (s.lock.lockShared()) {
        if (s.sameKey(key))
            s.waitingToBeFreed = true; // mark to free it later
        s.lock.unlockShared();
    } else {
        // we cannot be sure that the entry we found is ours because we do not
        // have a lock on it, but we still check to minimize false deletions
        if (s.sameKey(key))
            s.waitingToBeFreed = true; // mark to free it later
    }
}

/// unconditionally frees an already locked chain of slots, unlocking if needed
void
Ipc::StoreMap::freeChain(const sfileno fileno, Anchor &inode, const bool keepLocked)
{
    debugs(54, 7, "freeing entry " << fileno <<
           " in " << path);
    if (!inode.empty()) {
        sfileno sliceId = inode.start;
        debugs(54, 8, "first slice " << sliceId);
        while (sliceId >= 0) {
            Slice &slice = sliceAt(sliceId);
            const sfileno nextId = slice.next;
            slice.size = 0;
            slice.next = -1;
            if (cleaner)
                cleaner->noteFreeMapSlice(sliceId); // might change slice state
            sliceId = nextId;
        }
    }

    inode.waitingToBeFreed = false;
    inode.rewind();

    if (!keepLocked)
        inode.lock.unlockExclusive();
    --anchors->count;
    debugs(54, 5, "freed entry " << fileno << " in " << path);
}

const Ipc::StoreMap::Anchor *
Ipc::StoreMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, "opening entry with key " << storeKeyText(key)
           << " for reading " << path);
    const int idx = anchorIndexByKey(key);
    if (const Anchor *slot = openForReadingAt(idx)) {
        if (slot->sameKey(key)) {
            fileno = idx;
            return slot; // locked for reading
        }
        slot->lock.unlockShared();
        debugs(54, 7, "closed entry " << idx << " for reading " << path);
    }
    return NULL;
}

const Ipc::StoreMap::Anchor *
Ipc::StoreMap::openForReadingAt(const sfileno fileno)
{
    debugs(54, 5, "opening entry " << fileno << " for reading " << path);
    Anchor &s = anchorAt(fileno);

    if (!s.lock.lockShared()) {
        debugs(54, 5, "cannot open busy entry " << fileno <<
               " for reading " << path);
        return NULL;
    }

    if (s.empty()) {
        s.lock.unlockShared();
        debugs(54, 7, "cannot open empty entry " << fileno <<
               " for reading " << path);
        return NULL;
    }

    if (s.waitingToBeFreed) {
        s.lock.unlockShared();
        debugs(54, 7, "cannot open marked entry " << fileno <<
               " for reading " << path);
        return NULL;
    }

    debugs(54, 5, "opened entry " << fileno << " for reading " << path);
    return &s;
}

void
Ipc::StoreMap::closeForReading(const sfileno fileno)
{
    Anchor &s = anchorAt(fileno);
    assert(s.reading());
    s.lock.unlockShared();
    debugs(54, 5, "closed entry " << fileno << " for reading " << path);
}

bool
Ipc::StoreMap::purgeOne()
{
    // Hopefully, we find a removable entry much sooner (TODO: use time?).
    // The min() will protect us from division by zero inside the loop.
    const int searchLimit = min(10000, entryLimit());
    int tries = 0;
    for (; tries < searchLimit; ++tries) {
        const sfileno fileno = static_cast<sfileno>(++anchors->victim % entryLimit());
        Anchor &s = anchorAt(fileno);
        if (s.lock.lockExclusive()) {
            // the caller wants a free slice; empty anchor is not enough
            if (!s.empty() && s.start >= 0) {
                // this entry may be marked for deletion, and that is OK
                freeChain(fileno, s, false);
                debugs(54, 5, "purged entry " << fileno << " from " << path);
                return true;
            }
            s.lock.unlockExclusive();
        }
    }
    debugs(54, 5, "no entries to purge from " << path << "; tried: " << tries);
    return false;
}

void
Ipc::StoreMap::importSlice(const SliceId sliceId, const Slice &slice)
{
    // Slices are imported into positions that should not be available via
    // "get free slice" API. This is not something we can double check
    // reliably because the anchor for the imported slice may not have been
    // imported yet.
    assert(validSlice(sliceId));
    sliceAt(sliceId) = slice;
}

int
Ipc::StoreMap::entryLimit() const
{
    return min(sliceLimit(), static_cast<int>(SwapFilenMax+1));
}

int
Ipc::StoreMap::entryCount() const
{
    return anchors->count;
}

int
Ipc::StoreMap::sliceLimit() const
{
    return slices->capacity;
}

void
Ipc::StoreMap::updateStats(ReadWriteLockStats &stats) const
{
    for (int i = 0; i < anchors->capacity; ++i)
        anchorAt(i).lock.updateStats(stats);
}

bool
Ipc::StoreMap::validEntry(const int pos) const
{
    return 0 <= pos && pos < entryLimit();
}

bool
Ipc::StoreMap::validSlice(const int pos) const
{
    return 0 <= pos && pos < sliceLimit();
}

Ipc::StoreMap::Anchor&
Ipc::StoreMap::anchorAt(const sfileno fileno)
{
    assert(validEntry(fileno));
    return anchors->items[fileno];
}

const Ipc::StoreMap::Anchor&
Ipc::StoreMap::anchorAt(const sfileno fileno) const
{
    return const_cast<StoreMap&>(*this).anchorAt(fileno);
}

sfileno
Ipc::StoreMap::anchorIndexByKey(const cache_key *const key) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(key);
    // TODO: use a better hash function
    return (k[0] + k[1]) % entryLimit();
}

Ipc::StoreMap::Anchor &
Ipc::StoreMap::anchorByKey(const cache_key *const key)
{
    return anchorAt(anchorIndexByKey(key));
}

Ipc::StoreMap::Slice&
Ipc::StoreMap::sliceAt(const SliceId sliceId)
{
    assert(validSlice(sliceId));
    return slices->items[sliceId];
}

const Ipc::StoreMap::Slice&
Ipc::StoreMap::sliceAt(const SliceId sliceId) const
{
    return const_cast<StoreMap&>(*this).sliceAt(sliceId);
}

/* Ipc::StoreMapAnchor */

Ipc::StoreMapAnchor::StoreMapAnchor(): start(0)
{
    memset(&key, 0, sizeof(key));
    memset(&basics, 0, sizeof(basics));
    // keep in sync with rewind()
}

void
Ipc::StoreMapAnchor::setKey(const cache_key *const aKey)
{
    memcpy(key, aKey, sizeof(key));
}

bool
Ipc::StoreMapAnchor::sameKey(const cache_key *const aKey) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(aKey);
    return k[0] == key[0] && k[1] == key[1];
}

void
Ipc::StoreMapAnchor::set(const StoreEntry &from)
{
    assert(writing() && !reading());
    memcpy(key, from.key, sizeof(key));
    basics.timestamp = from.timestamp;
    basics.lastref = from.lastref;
    basics.expires = from.expires;
    basics.lastmod = from.lastModified();
    basics.swap_file_sz = from.swap_file_sz;
    basics.refcount = from.refcount;
    basics.flags = from.flags;
}

void
Ipc::StoreMapAnchor::rewind()
{
    assert(writing());
    start = 0;
    memset(&key, 0, sizeof(key));
    memset(&basics, 0, sizeof(basics));
    // but keep the lock
}

Ipc::StoreMap::Owner::Owner(): anchors(NULL), slices(NULL)
{
}

Ipc::StoreMap::Owner::~Owner()
{
    delete anchors;
    delete slices;
}

/* Ipc::StoreMapAnchors */

Ipc::StoreMapAnchors::StoreMapAnchors(const int aCapacity):
    count(0),
    victim(0),
    capacity(aCapacity),
    items(aCapacity)
{
}

size_t
Ipc::StoreMapAnchors::sharedMemorySize() const
{
    return SharedMemorySize(capacity);
}

size_t
Ipc::StoreMapAnchors::SharedMemorySize(const int capacity)
{
    return sizeof(StoreMapAnchors) + capacity * sizeof(StoreMapAnchor);
}

