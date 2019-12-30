/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/StoreMap.h"
#include "sbuf/SBuf.h"
#include "Store.h"
#include "store/Controller.h"
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

static SBuf
StoreMapFileNosId(const SBuf &path)
{
    return Ipc::Mem::Segment::Name(path, "filenos");
}

Ipc::StoreMap::Owner *
Ipc::StoreMap::Init(const SBuf &path, const int sliceLimit)
{
    assert(sliceLimit > 0); // we should not be created otherwise
    const int anchorLimit = min(sliceLimit, static_cast<int>(SwapFilenMax));
    Owner *owner = new Owner;
    owner->fileNos = shm_new(FileNos)(StoreMapFileNosId(path).c_str(), anchorLimit);
    owner->anchors = shm_new(Anchors)(StoreMapAnchorsId(path).c_str(), anchorLimit);
    owner->slices = shm_new(Slices)(StoreMapSlicesId(path).c_str(), sliceLimit);
    debugs(54, 5, "created " << path << " with " << anchorLimit << '+' << sliceLimit);
    return owner;
}

Ipc::StoreMap::StoreMap(const SBuf &aPath): cleaner(NULL), path(aPath),
    fileNos(shm_old(FileNos)(StoreMapFileNosId(path).c_str())),
    anchors(shm_old(Anchors)(StoreMapAnchorsId(path).c_str())),
    slices(shm_old(Slices)(StoreMapSlicesId(path).c_str()))
{
    debugs(54, 5, "attached " << path << " with " <<
           fileNos->capacity << '+' <<
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
    const int idx = fileNoByKey(key);

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
        s.splicingPoint = -1;
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
Ipc::StoreMap::closeForWriting(const sfileno fileno)
{
    Anchor &s = anchorAt(fileno);
    assert(s.writing());
    // TODO: assert(!s.empty()); // i.e., unlocked s becomes s.complete()
    s.lock.unlockExclusive();
    debugs(54, 5, "closed entry " << fileno << " for writing " << path);
    // cannot assert completeness here because we have no lock
}

void
Ipc::StoreMap::switchWritingToReading(const sfileno fileno)
{
    debugs(54, 5, "switching entry " << fileno << " from writing to reading " << path);
    Anchor &s = anchorAt(fileno);
    assert(s.writing());
    s.lock.switchExclusiveToShared();
    assert(s.complete());
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
        s.writerHalted = true;
        s.lock.unlockExclusive();
        debugs(54, 5, "closed dirty entry " << fileno << " for writing " << path);
    }
}

void
Ipc::StoreMap::abortUpdating(Update &update)
{
    const sfileno fileno = update.stale.fileNo;
    debugs(54, 5, "aborting entry " << fileno << " for updating " << path);
    if (update.stale) {
        AssertFlagIsSet(update.stale.anchor->lock.updating);
        update.stale.anchor->lock.unlockHeaders();
        closeForReading(update.stale.fileNo);
        update.stale = Update::Edition();
    }
    if (update.fresh) {
        abortWriting(update.fresh.fileNo);
        update.fresh = Update::Edition();
    }
    debugs(54, 5, "aborted entry " << fileno << " for updating " << path);
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

bool
Ipc::StoreMap::freeEntry(const sfileno fileno)
{
    debugs(54, 5, "marking entry " << fileno << " to be freed in " << path);

    Anchor &s = anchorAt(fileno);

    if (s.lock.lockExclusive()) {
        const bool result = !s.waitingToBeFreed && !s.empty();
        freeChain(fileno, s, false);
        return result;
    }

    uint8_t expected = false;
    // mark to free the locked entry later (if not already marked)
    return s.waitingToBeFreed.compare_exchange_strong(expected, true);
}

void
Ipc::StoreMap::freeEntryByKey(const cache_key *const key)
{
    debugs(54, 5, "marking entry with key " << storeKeyText(key)
           << " to be freed in " << path);

    const int idx = fileNoByKey(key);
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

bool
Ipc::StoreMap::markedForDeletion(const cache_key *const key)
{
    const int idx = fileNoByKey(key);
    const Anchor &s = anchorAt(idx);
    return s.sameKey(key) ? bool(s.waitingToBeFreed) : false;
}

bool
Ipc::StoreMap::hasReadableEntry(const cache_key *const key)
{
    sfileno index;
    if (openForReading(reinterpret_cast<const cache_key*>(key), index)) {
        closeForReading(index);
        return true;
    }
    return false;
}

/// unconditionally frees an already locked chain of slots, unlocking if needed
void
Ipc::StoreMap::freeChain(const sfileno fileno, Anchor &inode, const bool keepLocked)
{
    debugs(54, 7, "freeing entry " << fileno <<
           " in " << path);
    if (!inode.empty())
        freeChainAt(inode.start, inode.splicingPoint);
    inode.rewind();

    if (!keepLocked)
        inode.lock.unlockExclusive();
    --anchors->count;
    debugs(54, 5, "freed entry " << fileno << " in " << path);
}

/// unconditionally frees an already locked chain of slots; no anchor maintenance
void
Ipc::StoreMap::freeChainAt(SliceId sliceId, const SliceId splicingPoint)
{
    static uint64_t ChainId = 0; // to pair freeing/freed calls in debugs()
    const uint64_t chainId = ++ChainId;
    debugs(54, 7, "freeing chain #" << chainId << " starting at " << sliceId << " in " << path);
    while (sliceId >= 0) {
        Slice &slice = sliceAt(sliceId);
        const SliceId nextId = slice.next;
        slice.clear();
        if (cleaner)
            cleaner->noteFreeMapSlice(sliceId); // might change slice state
        if (sliceId == splicingPoint) {
            debugs(54, 5, "preserving chain #" << chainId << " in " << path <<
                   " suffix after slice " << splicingPoint);
            break; // do not free the rest of the chain
        }
        sliceId = nextId;
    }
    debugs(54, 7, "freed chain #" << chainId << " in " << path);
}

void
Ipc::StoreMap::prepFreeSlice(const SliceId sliceId)
{
    // TODO: Move freeSlots here, along with reserveSlotForWriting() logic.
    assert(validSlice(sliceId));
    sliceAt(sliceId).clear();
}

Ipc::StoreMap::SliceId
Ipc::StoreMap::sliceContaining(const sfileno fileno, const uint64_t bytesNeeded) const
{
    const Anchor &anchor = anchorAt(fileno);
    Must(anchor.reading());
    uint64_t bytesSeen = 0;
    SliceId lastSlice = anchor.start;
    while (lastSlice >= 0) {
        const Slice &slice = sliceAt(lastSlice);
        bytesSeen += slice.size;
        if (bytesSeen >= bytesNeeded)
            break;
        lastSlice = slice.next;
    }
    debugs(54, 7, "entry " << fileno << " has " << bytesNeeded << '/' << bytesSeen <<
           " bytes at slice " << lastSlice << " in " << path);
    return lastSlice; // may be negative
}

const Ipc::StoreMap::Anchor *
Ipc::StoreMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, "opening entry with key " << storeKeyText(key)
           << " for reading " << path);
    const int idx = fileNoByKey(key);
    if (const Anchor *slot = openForReadingAt(idx)) {
        if (slot->sameKey(key)) {
            fileno = idx;
            return slot; // locked for reading
        }
        slot->lock.unlockShared();
        debugs(54, 7, "closed wrong-key entry " << idx << " for reading " << path);
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
Ipc::StoreMap::openForUpdating(Update &update, const sfileno fileNoHint)
{
    Must(update.entry);
    const StoreEntry &entry = *update.entry;
    const cache_key *const key = reinterpret_cast<const cache_key*>(entry.key);
    update.stale.name = nameByKey(key);

    if (!validEntry(fileNoHint)) {
        debugs(54, 5, "opening entry with key " << storeKeyText(key) <<
               " for updating " << path);
        update.stale.fileNo = fileNoByName(update.stale.name);
    } else {
        update.stale.fileNo = fileNoHint;
    }

    debugs(54, 5, "opening entry " << update.stale.fileNo << " of " << entry << " for updating " << path);

    // Unreadable entries cannot (e.g., empty and otherwise problematic entries)
    // or should not (e.g., entries still forming their metadata) be updated.
    if (const Anchor *anchor = openForReadingAt(update.stale.fileNo)) {
        if (!anchor->sameKey(key)) {
            closeForReading(update.stale.fileNo);
            debugs(54, 5, "cannot open wrong-key entry " << update.stale.fileNo << " for updating " << path);
            return false;
        }
    } else {
        debugs(54, 5, "cannot open unreadable entry " << update.stale.fileNo << " for updating " << path);
        return false;
    }

    update.stale.anchor = &anchorAt(update.stale.fileNo);
    if (update.stale.anchor->writing()) {
        // TODO: Support updating appending entries.
        // For example, MemStore::updateHeaders() would not know how
        // many old prefix body bytes to copy to the new prefix if the last old
        // prefix slice has not been formed yet (i.e., still gets more bytes).
        debugs(54, 5, "cannot open appending entry " << update.stale.fileNo <<
               " for updating " << path);
        closeForReading(update.stale.fileNo);
        return false;
    }

    if (!update.stale.anchor->lock.lockHeaders()) {
        debugs(54, 5, "cannot open updating entry " << update.stale.fileNo <<
               " for updating " << path);
        closeForReading(update.stale.fileNo);
        return false;
    }

    /* stale anchor is properly locked; we can now use abortUpdating() if needed */

    if (!openKeyless(update.fresh)) {
        debugs(54, 5, "cannot open freshchainless entry " << update.stale.fileNo <<
               " for updating " << path);
        abortUpdating(update);
        return false;
    }

    Must(update.stale);
    Must(update.fresh);
    update.fresh.anchor->set(entry);
    debugs(54, 5, "opened entry " << update.stale.fileNo << " for updating " << path <<
           " using entry " << update.fresh.fileNo << " of " << entry);

    return true;
}

/// finds an anchor that is currently not associated with any entry key and
/// locks it for writing so ensure exclusive access during updates
bool
Ipc::StoreMap::openKeyless(Update::Edition &edition)
{
    return visitVictims([&](const sfileno name) {
        Update::Edition temp;
        temp.name = name;
        temp.fileNo = fileNoByName(temp.name);
        if ((temp.anchor = openForWritingAt(temp.fileNo))) {
            debugs(54, 5, "created entry " << temp.fileNo <<
                   " for updating " << path);
            Must(temp);
            edition = temp;
            return true;
        }
        return false;
    });
}

void
Ipc::StoreMap::closeForUpdating(Update &update)
{
    Must(update.stale.anchor);
    Must(update.fresh.anchor);
    AssertFlagIsSet(update.stale.anchor->lock.updating);
    Must(update.stale.splicingPoint >= 0);
    Must(update.fresh.splicingPoint >= 0);

    /* the stale prefix cannot overlap with the fresh one (a weak check) */
    Must(update.stale.anchor->start != update.fresh.anchor->start);
    Must(update.stale.anchor->start != update.fresh.splicingPoint);
    Must(update.stale.splicingPoint != update.fresh.anchor->start);
    Must(update.stale.splicingPoint != update.fresh.splicingPoint);

    /* the relative order of most operations is significant here */

    /* splice the fresh chain prefix with the stale chain suffix */
    Slice &freshSplicingSlice = sliceAt(update.fresh.splicingPoint);
    const SliceId suffixStart = sliceAt(update.stale.splicingPoint).next; // may be negative
    // the fresh chain is either properly terminated or already spliced
    if (freshSplicingSlice.next < 0)
        freshSplicingSlice.next = suffixStart;
    else
        Must(freshSplicingSlice.next == suffixStart);
    // either way, fresh chain uses the stale chain suffix now

    // make the fresh anchor/chain readable for everybody
    update.fresh.anchor->lock.switchExclusiveToShared();
    // but the fresh anchor is still invisible to anybody but us

    // This freeEntry() code duplicates the code below to minimize the time when
    // the freeEntry() race condition (see the Race: comment below) might occur.
    if (update.stale.anchor->waitingToBeFreed)
        freeEntry(update.fresh.fileNo);

    /* any external changes were applied to the stale anchor/chain until now */
    relocate(update.stale.name, update.fresh.fileNo);
    /* any external changes will apply to the fresh anchor/chain from now on */

    // Race: If the stale entry was deleted by some kid during the assignment,
    // then we propagate that event to the fresh anchor and chain. Since this
    // update is not atomically combined with the assignment above, another kid
    // might get a fresh entry just before we have a chance to free it. However,
    // such deletion races are always possible even without updates.
    if (update.stale.anchor->waitingToBeFreed)
        freeEntry(update.fresh.fileNo);

    /* free the stale chain prefix except for the shared suffix */
    update.stale.anchor->splicingPoint = update.stale.splicingPoint;
    freeEntry(update.stale.fileNo);

    // Make the stale anchor/chain reusable, reachable via update.fresh.name. If
    // update.entry->swap_filen is still update.stale.fileNo, and the entry is
    // using store, then the entry must have a lock on update.stale.fileNo,
    // preventing its premature reuse by others.
    relocate(update.fresh.name, update.stale.fileNo);

    const Update updateSaved = update; // for post-close debugging below

    /* unlock the stale anchor/chain */
    update.stale.anchor->lock.unlockHeaders();
    closeForReading(update.stale.fileNo);
    update.stale = Update::Edition();

    // finally, unlock the fresh entry
    closeForReading(update.fresh.fileNo);
    update.fresh = Update::Edition();

    debugs(54, 5, "closed entry " << updateSaved.stale.fileNo << " of " << *updateSaved.entry <<
           " named " << updateSaved.stale.name << " for updating " << path <<
           " to fresh entry " << updateSaved.fresh.fileNo << " named " << updateSaved.fresh.name <<
           " with [" << updateSaved.fresh.anchor->start << ',' << updateSaved.fresh.splicingPoint <<
           "] prefix containing at least " << freshSplicingSlice.size << " bytes");
}

/// Visits entries until either
/// * the `visitor` returns true (indicating its satisfaction with the offer);
/// * we give up finding a suitable entry because it already took "too long"; or
/// * we have offered all entries.
bool
Ipc::StoreMap::visitVictims(const NameFilter visitor)
{
    // Hopefully, we find a usable entry much sooner (TODO: use time?).
    // The min() will protect us from division by zero inside the loop.
    const int searchLimit = min(10000, entryLimit());
    int tries = 0;
    for (; tries < searchLimit; ++tries) {
        const sfileno name = static_cast<sfileno>(++anchors->victim % entryLimit());
        if (visitor(name))
            return true;
    }

    debugs(54, 5, "no victims found in " << path << "; tried: " << tries);
    return false;
}

bool
Ipc::StoreMap::purgeOne()
{
    return visitVictims([&](const sfileno name) {
        const sfileno fileno = fileNoByName(name);
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
        return false;
    });
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
Ipc::StoreMap::nameByKey(const cache_key *const key) const
{
    assert(key);
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(key);
    // TODO: use a better hash function
    const int hash = (k[0] + k[1]) % entryLimit();
    return hash;
}

sfileno
Ipc::StoreMap::fileNoByName(const sfileno name) const
{
    // fileNos->items are initialized to zero, which we treat as "name is fileno";
    // a positive value means the entry anchor got moved to a new fileNo
    if (const int item = fileNos->items[name])
        return item-1;
    return name;
}

/// map `name` to `fileNo`
void
Ipc::StoreMap::relocate(const sfileno name, const sfileno fileno)
{
    // preserve special meaning for zero; see fileNoByName
    fileNos->items[name] = fileno+1;
}

sfileno
Ipc::StoreMap::fileNoByKey(const cache_key *const key) const
{
    const int name = nameByKey(key);
    return fileNoByName(name);
}

Ipc::StoreMap::Anchor &
Ipc::StoreMap::anchorByKey(const cache_key *const key)
{
    return anchorAt(fileNoByKey(key));
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

Ipc::StoreMapAnchor::StoreMapAnchor(): start(0), splicingPoint(-1)
{
    // keep in sync with rewind()
}

void
Ipc::StoreMapAnchor::setKey(const cache_key *const aKey)
{
    memcpy(key, aKey, sizeof(key));
    waitingToBeFreed = Store::Root().markedForDeletion(aKey);
}

bool
Ipc::StoreMapAnchor::sameKey(const cache_key *const aKey) const
{
    const uint64_t *const k = reinterpret_cast<const uint64_t *>(aKey);
    return k[0] == key[0] && k[1] == key[1];
}

void
Ipc::StoreMapAnchor::set(const StoreEntry &from, const cache_key *aKey)
{
    assert(writing() && !reading());
    setKey(reinterpret_cast<const cache_key*>(aKey ? aKey : from.key));
    basics.timestamp = from.timestamp;
    basics.lastref = from.lastref;
    basics.expires = from.expires;
    basics.lastmod = from.lastModified();
    basics.swap_file_sz = from.swap_file_sz;
    basics.refcount = from.refcount;

    // do not copy key bit if we are not using from.key
    // TODO: Replace KEY_PRIVATE with a nil StoreEntry::key!
    uint16_t cleanFlags = from.flags;
    if (aKey)
        EBIT_CLR(cleanFlags, KEY_PRIVATE);
    basics.flags = cleanFlags;
}

void
Ipc::StoreMapAnchor::exportInto(StoreEntry &into) const
{
    assert(reading());
    into.timestamp = basics.timestamp;
    into.lastref = basics.lastref;
    into.expires = basics.expires;
    into.lastModified(basics.lastmod);
    into.swap_file_sz = basics.swap_file_sz;
    into.refcount = basics.refcount;
    const bool collapsingRequired = into.hittingRequiresCollapsing();
    into.flags = basics.flags;
    // There are possibly several flags we do not need to overwrite,
    // and ENTRY_REQUIRES_COLLAPSING is one of them.
    // TODO: check for other flags.
    into.setCollapsingRequirement(collapsingRequired);
}

void
Ipc::StoreMapAnchor::rewind()
{
    assert(writing());
    start = 0;
    splicingPoint = -1;
    memset(&key, 0, sizeof(key));
    basics.clear();
    waitingToBeFreed = false;
    writerHalted = false;
    // but keep the lock
}

/* Ipc::StoreMapUpdate */

Ipc::StoreMapUpdate::StoreMapUpdate(StoreEntry *anEntry):
    entry(anEntry)
{
    entry->lock("Ipc::StoreMapUpdate1");
}

Ipc::StoreMapUpdate::StoreMapUpdate(const StoreMapUpdate &other):
    entry(other.entry),
    stale(other.stale),
    fresh(other.fresh)
{
    entry->lock("Ipc::StoreMapUpdate2");
}

Ipc::StoreMapUpdate::~StoreMapUpdate()
{
    entry->unlock("Ipc::StoreMapUpdate");
}

/* Ipc::StoreMap::Owner */

Ipc::StoreMap::Owner::Owner():
    fileNos(nullptr),
    anchors(nullptr),
    slices(nullptr)
{
}

Ipc::StoreMap::Owner::~Owner()
{
    delete fileNos;
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

