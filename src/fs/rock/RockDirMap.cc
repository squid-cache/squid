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

Rock::StoreEntryBasics *
Rock::DirMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    debugs(79, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    const int idx = slotIdx(key);
    Slot &s = shared->slots[idx];

    if (s.exclusiveLock()) {
        assert(s.state != Slot::Writeable); // until we start breaking locks
        if (s.state == Slot::Empty) // we may also overwrite a Readable slot
            ++shared->count;
        s.state = Slot::Writeable;
        s.setKey(key);
        fileno = idx;
        debugs(79, 5, HERE << " opened slot at " << fileno << " for key " <<
               storeKeyText(key) << " for writing in map [" << path << ']');
        return &s.seBasics; // and keep the entry locked
    }

    debugs(79, 5, HERE << " failed to open slot at " << idx << " for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    return NULL;
}

void
Rock::DirMap::closeForWriting(const sfileno fileno)
{
    debugs(79, 5, HERE << " closing slot at " << fileno << " for writing and "
           "openning for reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state.swap_if(Slot::Writeable, Slot::Readable));
    s.switchExclusiveToSharedLock();
}

/// terminate writing the entry, freeing its slot for others to use
void
Rock::DirMap::abortWriting(const sfileno fileno)
{
    debugs(79, 5, HERE << " abort writing slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    assert(s.state == Slot::Writeable);
    freeLocked(s);
}

void
Rock::DirMap::abortIo(const sfileno fileno)
{
    debugs(79, 5, HERE << " abort I/O for slot at " << fileno <<
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

const Rock::StoreEntryBasics *
Rock::DirMap::peekAtReader(const sfileno fileno) const
{
    assert(valid(fileno));
    const Slot &s = shared->slots[fileno];
    switch (s.state) {
    case Slot::Readable:
        return &s.seBasics; // immediate access by lock holder so no locking
    case Slot::Writeable:
        return NULL; // cannot read the slot when it is being written
    case Slot::Empty:
        assert(false); // must be locked for reading or writing
    }
    assert(false); // not reachable
    return NULL;
}

bool
Rock::DirMap::putAt(const DbCellHeader &header, const StoreEntry &e,
                    const sfileno fileno)
{
    const cache_key *key = static_cast<const cache_key*>(e.key);
    debugs(79, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for putting in map [" << path << ']');
    if (!valid(fileno)) {
        debugs(79, 5, HERE << "failure: bad fileno: " << fileno);
        return false;
    }
    
    const int idx = slotIdx(key);
    if (fileno != idx) {
        debugs(79, 5, HERE << "failure: hash changed: " << idx << " vs. " <<
            fileno);
        return false;
    }
    
    Slot &s = shared->slots[idx];

    if (s.exclusiveLock()) {
        assert(s.state != Slot::Writeable); // until we start breaking locks
        if (s.state == Slot::Empty) // we may also overwrite a Readable slot
            ++shared->count;
        s.setKey(static_cast<const cache_key*>(e.key));
        s.seBasics.set(header, e);
        s.state = Slot::Readable;
        s.releaseExclusiveLock();
        debugs(79, 5, HERE << " put slot at " << fileno << " for key " <<
               storeKeyText(key) << " in map [" << path << ']');
        return true;
    }

    debugs(79, 5, HERE << " failed to open slot for key " << storeKeyText(key)
           << " for putting in map [" << path << ']');
    return false;
}

void
Rock::DirMap::free(const sfileno fileno)
{
    debugs(79, 5, HERE << " marking slot at " << fileno << " to be freed in"
               " map [" << path << ']');

    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    s.waitingToBeFreed = true; // mark, regardless of whether we can free
    freeIfNeeded(s);
}

const Rock::StoreEntryBasics *
Rock::DirMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(79, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    const int idx = slotIdx(key);
    if (const StoreEntryBasics *const seBasics = openForReadingAt(idx)) {
        Slot &s = shared->slots[idx];
        if (s.checkKey(key)) {
            fileno = idx;
            debugs(79, 5, HERE << " opened slot at " << fileno << " for key "
                   << storeKeyText(key) << " for reading in map [" << path <<
                   ']');
            return seBasics;
        }
        s.releaseSharedLock();
        freeIfNeeded(s);
    }
    debugs(79, 5, HERE << " failed to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    return 0;
}

const Rock::StoreEntryBasics *
Rock::DirMap::openForReadingAt(const sfileno fileno)
{
    debugs(79, 5, HERE << " trying to open slot at " << fileno << " for "
           "reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = shared->slots[fileno];
    if (s.sharedLock()) {
        debugs(79, 5, HERE << " opened slot at " << fileno << " for reading in"
               " map [" << path << ']');
        return &s.seBasics;
    }
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
    assert(s.state == Slot::Readable);
    s.releaseSharedLock();
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

void
Rock::DirMap::updateStats(MapStats &stats) const
{
    stats.capacity += shared->limit;
    for (int i = 0; i < shared->limit; ++i)
        shared->slots[i].updateStats(stats);
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

Rock::Slot &
Rock::DirMap::slot(const cache_key *const key)
{
    return shared->slots[slotIdx(key)];
}

/// frees the slot if (b) it is waiting to be freed and (a) we can lock it
void
Rock::DirMap::freeIfNeeded(Slot &s)
{
    if (s.exclusiveLock()) {
        if (s.waitingToBeFreed == true)
            freeLocked(s);
        else
            s.releaseExclusiveLock();
    }
}

/// unconditionally frees the already exclusively locked slot and releases lock
void
Rock::DirMap::freeLocked(Slot &s)
{
    memset(s.key_, 0, sizeof(s.key_));
    memset(&s.seBasics, 0, sizeof(s.seBasics));
    s.waitingToBeFreed = false;
    s.state = Slot::Empty;
    s.releaseExclusiveLock();
    --shared->count;
    debugs(79, 5, HERE << " freed slot at " << (&s - shared->slots) <<
           " in map [" << path << ']');
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


/* Rock::Slot */

void
Rock::Slot::setKey(const cache_key *const aKey)
{
    memcpy(key_, aKey, sizeof(key_));
}

bool
Rock::Slot::checkKey(const cache_key *const aKey) const
{
    const uint32_t *const k = reinterpret_cast<const uint32_t *>(aKey);
    return k[0] == key_[0] && k[1] == key_[1] &&
           k[2] == key_[2] && k[3] == key_[3];
}


bool
Rock::Slot::sharedLock() const
{
    ++readers; // this locks new writers out
    if (state == Readable && !writers && !waitingToBeFreed)
        return true;
    --readers;
    return false;
}

bool
Rock::Slot::exclusiveLock()
{
    if (!writers++) { // we are the first writer (this locks new readers out)
        if (!readers) // there are no old readers
            return true;
	}
    --writers;
    return false;
}

void
Rock::Slot::releaseSharedLock() const
{
    assert(readers-- > 0);
}

void
Rock::Slot::releaseExclusiveLock()
{
    assert(writers-- > 0);
}

void
Rock::Slot::switchExclusiveToSharedLock()
{
    ++readers; // must be done before we release exclusive control
    releaseExclusiveLock();
}

void
Rock::Slot::updateStats(MapStats &stats) const
{
    switch (state) {
    case Readable:
        ++stats.readable;
        stats.readers += readers;
        break;
    case Writeable:
        ++stats.writeable;
        stats.writers += writers;
        break;
    case Empty:
        ++stats.empty;
        break;
    }

    if (waitingToBeFreed)
        ++stats.marked;
}


Rock::DirMap::Shared::Shared(const int aLimit): limit(aLimit), count(0)
{
}

void
Rock::StoreEntryBasics::set(const DbCellHeader &aHeader, const StoreEntry &from)
{
    assert(from.swap_file_sz > 0);
    memset(this, 0, sizeof(*this));
    header = aHeader;
    timestamp = from.timestamp;
    lastref = from.lastref;
    expires = from.expires;
    lastmod = from.lastmod;
    swap_file_sz = from.swap_file_sz;
    refcount = from.refcount;
    flags = from.flags;
}


/* MapStats */

Rock::MapStats::MapStats()
{
    memset(this, 0, sizeof(*this));
}
 
void
Rock::MapStats::dump(StoreEntry &e) const
{
    storeAppendPrintf(&e, "Available slots: %9d\n", capacity);

    if (!capacity)
        return;

    storeAppendPrintf(&e, "Readable slots:  %9d %6.2f%%\n",
        readable, (100.0 * readable / capacity));
    storeAppendPrintf(&e, "Filling slots:   %9d %6.2f%%\n",
        writeable, (100.0 * writeable / capacity));
    storeAppendPrintf(&e, "Empty slots:     %9d %6.2f%%\n",
        empty, (100.0 * empty / capacity));

    if (readers || writers) {
        const int locks = readers + writers;
        storeAppendPrintf(&e, "Readers:         %9d %6.2f%%\n",
            readers, (100.0 * readers / locks));
        storeAppendPrintf(&e, "Writers:         %9d %6.2f%%\n",
            writers, (100.0 * writers / locks));
    }

    if (readable + writeable) {
        storeAppendPrintf(&e, "Marked slots:    %9d %6.2f%%\n",
            marked, (100.0 * marked / (readable + writeable)));
    }
}
