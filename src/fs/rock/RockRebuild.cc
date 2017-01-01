/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "disk.h"
#include "fs/rock/RockDbCell.h"
#include "fs/rock/RockRebuild.h"
#include "fs/rock/RockSwapDir.h"
#include "globals.h"
#include "ipc/StoreMap.h"
#include "md5.h"
#include "SquidTime.h"
#include "store_rebuild.h"
#include "tools.h"
#include "typedefs.h"

#include <cerrno>

CBDATA_NAMESPACED_CLASS_INIT(Rock, Rebuild);

/**
 \defgroup RockFsRebuild Rock Store Rebuild
 \ingroup Filesystems
 *
 \section Overview Overview
 *  Several layers of information are manipualted during the rebuild:
 \par
 *  Store Entry: Response message plus all the metainformation associated with
 *  it. Identified by store key. At any given time, from Squid point
 *  of view, there is only one entry with a given key, but several
 *  different entries with the same key can be observed in any historical
 *  archive (such as an access log or a store database).
 \par
 *  Slot chain: A sequence of db slots representing a Store Entry state at
 *  some point in time. Identified by key+version combination. Due to
 *  transaction aborts, crashes, and idle periods, some chains may contain
 *  incomplete or stale information. We assume that no two different chains
 *  have the same key and version. If that assumption fails, we may serve a
 *  hodgepodge entry during rebuild, until "extra" slots are loaded/noticed.
 \par
 *  Db slot: A db record containing a piece of a single store entry and linked
 *  to other slots with the same key and version fields, forming a chain.
 *  Slots are identified by their absolute position in the database file,
 *  which is naturally unique.
 \par
 *  Except for the "mapped", "freed", and "more" fields, LoadingEntry info is
 *  entry-level and is stored at fileno position. In other words, the array of
 *  LoadingEntries should be interpreted as two arrays, one that maps slot ID
 *  to the LoadingEntry::mapped/free/more members, and the second one that maps
 *  fileno to all other LoadingEntry members. StoreMap maps slot key to fileno.
 \par
 *  When information from the newly loaded db slot contradicts the entry-level
 *  information collected so far (e.g., the versions do not match or the total
 *  chain size after the slot contribution exceeds the expected number), the
 *  whole entry (and not just the chain or the slot!) is declared corrupted.
 \par
 *  Why invalidate the whole entry? Rock Store is written for high-load
 *  environments with large caches, where there is usually very few idle slots
 *  in the database. A space occupied by a purged entry is usually immediately
 *  reclaimed. A Squid crash or a transaction abort is rather unlikely to
 *  leave a relatively large number of stale slots in the database. Thus, the
 *  number of potentially corrupted entries is relatively small. On the other
 *  hand, the damage from serving a single hadgepodge entry may be significant
 *  to the user. In such an environment, invalidating the whole entry has
 *  negligible performance impact but saves us from high-damage bugs.
 */

namespace Rock
{

/// maintains information about the store entry being loaded from disk
/// used for identifying partially stored/loaded entries
class LoadingEntry
{
public:
    LoadingEntry(): size(0), version(0), state(leEmpty), anchored(0),
        mapped(0), freed(0), more(-1) {}

    /* store entry-level information indexed by sfileno */
    uint64_t size; ///< payload seen so far
    uint32_t version; ///< DbCellHeader::version to distinguish same-URL chains
    uint8_t state:3;  ///< current entry state (one of the State values)
    uint8_t anchored:1;  ///< whether we loaded the inode slot for this entry

    /* db slot-level information indexed by slotId, starting with firstSlot */
    uint8_t mapped:1;  ///< whether this slot was added to a mapped entry
    uint8_t freed:1;  ///< whether this slot was marked as free
    Ipc::StoreMapSliceId more; ///< another slot in some entry chain (unordered)
    bool used() const { return freed || mapped || more != -1; }

    /// possible entry states
    typedef enum { leEmpty = 0, leLoading, leLoaded, leCorrupted, leIgnored } State;
};

} /* namespace Rock */

Rock::Rebuild::Rebuild(SwapDir *dir): AsyncJob("Rock::Rebuild"),
    sd(dir),
    entries(NULL),
    dbSize(0),
    dbSlotSize(0),
    dbSlotLimit(0),
    dbEntryLimit(0),
    fd(-1),
    dbOffset(0),
    loadingPos(0),
    validationPos(0)
{
    assert(sd);
    memset(&counts, 0, sizeof(counts));
    dbSize = sd->diskOffsetLimit(); // we do not care about the trailer waste
    dbSlotSize = sd->slotSize;
    dbEntryLimit = sd->entryLimitActual();
    dbSlotLimit = sd->slotLimitActual();
    assert(dbEntryLimit <= dbSlotLimit);
}

Rock::Rebuild::~Rebuild()
{
    if (fd >= 0)
        file_close(fd);
    delete[] entries;
}

/// prepares and initiates entry loading sequence
void
Rock::Rebuild::start()
{
    // in SMP mode, only the disker is responsible for populating the map
    if (UsingSmp() && !IamDiskProcess()) {
        debugs(47, 2, "Non-disker skips rebuilding of cache_dir #" <<
               sd->index << " from " << sd->filePath);
        mustStop("non-disker");
        return;
    }

    debugs(47, DBG_IMPORTANT, "Loading cache_dir #" << sd->index <<
           " from " << sd->filePath);

    fd = file_open(sd->filePath, O_RDONLY | O_BINARY);
    if (fd < 0)
        failure("cannot open db", errno);

    char hdrBuf[SwapDir::HeaderSize];
    if (read(fd, hdrBuf, sizeof(hdrBuf)) != SwapDir::HeaderSize)
        failure("cannot read db header", errno);

    // slot prefix of SM_PAGE_SIZE should fit both core entry header and ours
    assert(sizeof(DbCellHeader) < SM_PAGE_SIZE);
    buf.init(SM_PAGE_SIZE, SM_PAGE_SIZE);

    dbOffset = SwapDir::HeaderSize;

    entries = new LoadingEntry[dbSlotLimit];

    checkpoint();
}

/// continues after a pause if not done
void
Rock::Rebuild::checkpoint()
{
    if (!done())
        eventAdd("Rock::Rebuild", Rock::Rebuild::Steps, this, 0.01, 1, true);
}

bool
Rock::Rebuild::doneAll() const
{
    return loadingPos >= dbSlotLimit && validationPos >= dbSlotLimit &&
           AsyncJob::doneAll();
}

void
Rock::Rebuild::Steps(void *data)
{
    // use async call to enable job call protection that time events lack
    CallJobHere(47, 5, static_cast<Rebuild*>(data), Rock::Rebuild, steps);
}

void
Rock::Rebuild::steps()
{
    if (loadingPos < dbSlotLimit)
        loadingSteps();
    else
        validationSteps();

    checkpoint();
}

void
Rock::Rebuild::loadingSteps()
{
    debugs(47,5, sd->index << " slot " << loadingPos << " at " <<
           dbOffset << " <= " << dbSize);

    // Balance our desire to maximize the number of entries processed at once
    // (and, hence, minimize overheads and total rebuild time) with a
    // requirement to also process Coordinator events, disk I/Os, etc.
    const int maxSpentMsec = 50; // keep small: most RAM I/Os are under 1ms
    const timeval loopStart = current_time;

    int loaded = 0;
    while (loadingPos < dbSlotLimit) {
        loadOneSlot();
        dbOffset += dbSlotSize;
        ++loadingPos;
        ++loaded;

        if (counts.scancount % 1000 == 0)
            storeRebuildProgress(sd->index, dbSlotLimit, counts.scancount);

        if (opt_foreground_rebuild)
            continue; // skip "few entries at a time" check below

        getCurrentTime();
        const double elapsedMsec = tvSubMsec(loopStart, current_time);
        if (elapsedMsec > maxSpentMsec || elapsedMsec < 0) {
            debugs(47, 5, HERE << "pausing after " << loaded << " entries in " <<
                   elapsedMsec << "ms; " << (elapsedMsec/loaded) << "ms per entry");
            break;
        }
    }
}

void
Rock::Rebuild::loadOneSlot()
{
    debugs(47,5, sd->index << " slot " << loadingPos << " at " <<
           dbOffset << " <= " << dbSize);

    ++counts.scancount;

    if (lseek(fd, dbOffset, SEEK_SET) < 0)
        failure("cannot seek to db entry", errno);

    buf.reset();

    if (!storeRebuildLoadEntry(fd, sd->index, buf, counts))
        return;

    const SlotId slotId = loadingPos;

    // get our header
    DbCellHeader header;
    if (buf.contentSize() < static_cast<mb_size_t>(sizeof(header))) {
        debugs(47, DBG_IMPORTANT, "WARNING: cache_dir[" << sd->index << "]: " <<
               "Ignoring truncated " << buf.contentSize() << "-byte " <<
               "cache entry meta data at " << dbOffset);
        freeSlotIfIdle(slotId, true);
        return;
    }
    memcpy(&header, buf.content(), sizeof(header));
    if (header.empty()) {
        freeSlotIfIdle(slotId, false);
        return;
    }
    if (!header.sane(dbSlotSize, dbSlotLimit)) {
        debugs(47, DBG_IMPORTANT, "WARNING: cache_dir[" << sd->index << "]: " <<
               "Ignoring malformed cache entry meta data at " << dbOffset);
        freeSlotIfIdle(slotId, true);
        return;
    }
    buf.consume(sizeof(header)); // optimize to avoid memmove()

    useNewSlot(slotId, header);
}

/// parse StoreEntry basics and add them to the map, returning true on success
bool
Rock::Rebuild::importEntry(Ipc::StoreMapAnchor &anchor, const sfileno fileno, const DbCellHeader &header)
{
    cache_key key[SQUID_MD5_DIGEST_LENGTH];
    StoreEntry loadedE;
    const uint64_t knownSize = header.entrySize > 0 ?
                               header.entrySize : anchor.basics.swap_file_sz.get();
    if (!storeRebuildParseEntry(buf, loadedE, key, counts, knownSize))
        return false;

    // the entry size may still be unknown at this time

    debugs(47, 8, "importing basics for entry " << fileno <<
           " swap_file_sz: " << loadedE.swap_file_sz);
    anchor.set(loadedE);

    // we have not validated whether all db cells for this entry were loaded
    EBIT_CLR(anchor.basics.flags, ENTRY_VALIDATED);

    // loadedE->dump(5);

    return true;
}

void
Rock::Rebuild::validationSteps()
{
    debugs(47, 5, sd->index << " validating from " << validationPos);

    // see loadingSteps() for the rationale; TODO: avoid duplication
    const int maxSpentMsec = 50; // keep small: validation does not do I/O
    const timeval loopStart = current_time;

    int validated = 0;
    while (validationPos < dbSlotLimit) {
        validateOneEntry();
        ++validationPos;
        ++validated;

        if (validationPos % 1000 == 0)
            debugs(20, 2, "validated: " << validationPos);

        if (opt_foreground_rebuild)
            continue; // skip "few entries at a time" check below

        getCurrentTime();
        const double elapsedMsec = tvSubMsec(loopStart, current_time);
        if (elapsedMsec > maxSpentMsec || elapsedMsec < 0) {
            debugs(47, 5, "pausing after " << validated << " entries in " <<
                   elapsedMsec << "ms; " << (elapsedMsec/validated) << "ms per entry");
            break;
        }
    }
}

void
Rock::Rebuild::validateOneEntry()
{
    LoadingEntry &e = entries[validationPos];
    switch (e.state) {

    case LoadingEntry::leEmpty:
        break; // no entry hashed to this position

    case LoadingEntry::leLoading:
        freeBadEntry(validationPos, "partially stored");
        break;

    case LoadingEntry::leLoaded:
        break; // we have already unlocked this entry

    case LoadingEntry::leCorrupted:
        break; // we have already removed this entry
    }
}

/// Marks remaining bad entry slots as free and unlocks the entry. The map
/// cannot do this because Loading entries may have holes in the slots chain.
void
Rock::Rebuild::freeBadEntry(const sfileno fileno, const char *eDescription)
{
    debugs(47, 2, "cache_dir #" << sd->index << ' ' << eDescription <<
           " entry " << fileno << " is ignored during rebuild");

    Ipc::StoreMapAnchor &anchor = sd->map->writeableEntry(fileno);

    bool freedSome = false;
    // free all loaded non-anchor slots
    SlotId slotId = entries[anchor.start].more;
    while (slotId >= 0) {
        const SlotId next = entries[slotId].more;
        freeSlot(slotId, false);
        slotId = next;
        freedSome = true;
    }
    // free anchor slot if it was loaded
    if (entries[fileno].anchored) {
        freeSlot(anchor.start, false);
        freedSome = true;
    }
    assert(freedSome);

    sd->map->forgetWritingEntry(fileno);
    ++counts.invalid;
}

void
Rock::Rebuild::swanSong()
{
    debugs(47,3, HERE << "cache_dir #" << sd->index << " rebuild level: " <<
           StoreController::store_dirs_rebuilding);
    --StoreController::store_dirs_rebuilding;
    storeRebuildComplete(&counts);
}

void
Rock::Rebuild::failure(const char *msg, int errNo)
{
    debugs(47,5, sd->index << " slot " << loadingPos << " at " <<
           dbOffset << " <= " << dbSize);

    if (errNo)
        debugs(47, DBG_CRITICAL, "ERROR: Rock cache_dir rebuild failure: " << xstrerr(errNo));
    debugs(47, DBG_CRITICAL, "Do you need to run 'squid -z' to initialize storage?");

    assert(sd);
    fatalf("Rock cache_dir[%d] rebuild of %s failed: %s.",
           sd->index, sd->filePath, msg);
}

/// adds slot to the free slot index
void
Rock::Rebuild::freeSlot(const SlotId slotId, const bool invalid)
{
    debugs(47,5, sd->index << " frees slot " << slotId);
    LoadingEntry &le = entries[slotId];
    assert(!le.freed);
    le.freed = 1;

    if (invalid) {
        ++counts.invalid;
        //sd->unlink(fileno); leave garbage on disk, it should not hurt
    }

    Ipc::Mem::PageId pageId;
    pageId.pool = sd->index+1;
    pageId.number = slotId+1;
    sd->freeSlots->push(pageId);
}

/// adds slot to the free slot index but only if the slot is unused
void
Rock::Rebuild::freeSlotIfIdle(const SlotId slotId, const bool invalid)
{
    const LoadingEntry &le = entries[slotId];

    // mapped slots must be freed via freeBadEntry() to keep the map in sync
    assert(!le.mapped);

    if (!le.used())
        freeSlot(slotId, invalid);
}

/// adds slot to the entry chain in the map
void
Rock::Rebuild::mapSlot(const SlotId slotId, const DbCellHeader &header)
{
    LoadingEntry &le = entries[slotId];
    assert(!le.mapped);
    assert(!le.freed);
    le.mapped = 1;

    Ipc::StoreMapSlice slice;
    slice.next = header.nextSlot;
    slice.size = header.payloadSize;
    sd->map->importSlice(slotId, slice);
}

/// adds slot to an existing entry chain; caller must check that the slot
/// belongs to the chain it is being added to
void
Rock::Rebuild::addSlotToEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header)
{
    LoadingEntry &le = entries[fileno];
    Ipc::StoreMapAnchor &anchor = sd->map->writeableEntry(fileno);

    assert(le.version == header.version);

    // mark anchor as loaded or add the secondary slot to the chain
    LoadingEntry &inode = entries[header.firstSlot];
    if (header.firstSlot == slotId) {
        debugs(47,5, "adding inode");
        assert(!inode.freed);
        le.anchored = 1;
    } else {
        debugs(47,9, "linking " << slotId << " to " << inode.more);
        // we do not need to preserve the order
        LoadingEntry &slice = entries[slotId];
        assert(!slice.freed);
        assert(slice.more < 0);
        slice.more = inode.more;
        inode.more = slotId;
    }

    if (header.firstSlot == slotId && !importEntry(anchor, fileno, header)) {
        le.state = LoadingEntry::leCorrupted;
        freeBadEntry(fileno, "corrupted metainfo");
        return;
    }

    // set total entry size and/or check it for consistency
    debugs(47, 8, "header.entrySize: " << header.entrySize << " swap_file_sz: " << anchor.basics.swap_file_sz);
    uint64_t totalSize = header.entrySize;
    assert(totalSize != static_cast<uint64_t>(-1));
    if (!totalSize && anchor.basics.swap_file_sz) {
        assert(anchor.basics.swap_file_sz != static_cast<uint64_t>(-1));
        // perhaps we loaded a later slot (with entrySize) earlier
        totalSize = anchor.basics.swap_file_sz;
    } else if (totalSize && !anchor.basics.swap_file_sz) {
        anchor.basics.swap_file_sz = totalSize;
        assert(anchor.basics.swap_file_sz != static_cast<uint64_t>(-1));
    } else if (totalSize != anchor.basics.swap_file_sz) {
        le.state = LoadingEntry::leCorrupted;
        freeBadEntry(fileno, "size mismatch");
        return;
    }

    le.size += header.payloadSize;

    if (totalSize > 0 && le.size > totalSize) { // overflow
        debugs(47, 8, "overflow: " << le.size << " > " << totalSize);
        le.state = LoadingEntry::leCorrupted;
        freeBadEntry(fileno, "overflowing");
        return;
    }

    mapSlot(slotId, header);
    if (totalSize > 0 && le.size == totalSize) {
        // entry fully loaded, unlock it
        // we have validated that all db cells for this entry were loaded
        EBIT_SET(anchor.basics.flags, ENTRY_VALIDATED);
        le.state = LoadingEntry::leLoaded;
        sd->map->closeForWriting(fileno, false);
        ++counts.objcount;
    }
}

/// initialize housekeeping information for a newly accepted entry
void
Rock::Rebuild::primeNewEntry(Ipc::StoreMap::Anchor &anchor, const sfileno fileno, const DbCellHeader &header)
{
    anchor.setKey(reinterpret_cast<const cache_key*>(header.key));
    assert(header.firstSlot >= 0);
    anchor.start = header.firstSlot;

    assert(anchor.basics.swap_file_sz != static_cast<uint64_t>(-1));

    LoadingEntry &le = entries[fileno];
    le.state = LoadingEntry::leLoading;
    le.version = header.version;
    le.size = 0;
}

/// handle a slot from an entry that we have not seen before
void
Rock::Rebuild::startNewEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header)
{
    // If some other from-disk entry is/was using this slot as its inode OR
    // if some other from-disk entry is/was using our inode slot, then the
    // entries are conflicting. We cannot identify other entries, so we just
    // remove ours and hope that the others were/will be handled correctly.
    const LoadingEntry &slice = entries[slotId];
    const LoadingEntry &inode = entries[header.firstSlot];
    if (slice.used() || inode.used()) {
        debugs(47,8, "slice/inode used: " << slice.used() << inode.used());
        LoadingEntry &le = entries[fileno];
        le.state = LoadingEntry::leCorrupted;
        freeSlotIfIdle(slotId, slotId == header.firstSlot);
        // if not idle, the other entry will handle its slice
        ++counts.clashcount;
        return;
    }

    // A miss may have been stored at our fileno while we were loading other
    // slots from disk. We ought to preserve that entry because it is fresher.
    const bool overwriteExisting = false;
    if (Ipc::StoreMap::Anchor *anchor = sd->map->openForWritingAt(fileno, overwriteExisting)) {
        primeNewEntry(*anchor, fileno, header);
        addSlotToEntry(fileno, slotId, header); // may fail
        assert(anchor->basics.swap_file_sz != static_cast<uint64_t>(-1));
    } else {
        // A new from-network entry is occupying our map slot; let it be, but
        // save us from the trouble of going through the above motions again.
        LoadingEntry &le = entries[fileno];
        le.state = LoadingEntry::leIgnored;
        freeSlotIfIdle(slotId, false);
    }
}

/// does the header belong to the fileno entry being loaded?
bool
Rock::Rebuild::sameEntry(const sfileno fileno, const DbCellHeader &header) const
{
    const Ipc::StoreMap::Anchor &anchor = sd->map->writeableEntry(fileno);
    const LoadingEntry &le = entries[fileno];
    // any order will work, but do fast comparisons first:
    return le.version == header.version &&
           anchor.start == static_cast<Ipc::StoreMapSliceId>(header.firstSlot) &&
           anchor.sameKey(reinterpret_cast<const cache_key*>(header.key));
}

/// is the new header consistent with information already loaded?
bool
Rock::Rebuild::canAdd(const sfileno fileno, const SlotId slotId, const DbCellHeader &header) const
{
    if (!sameEntry(fileno, header)) {
        debugs(79, 7, "cannot add; wrong entry");
        return false;
    }

    const LoadingEntry &le = entries[slotId];
    // We cannot add a slot that was already declared free or mapped.
    if (le.freed || le.mapped) {
        debugs(79, 7, "cannot add; freed/mapped: " << le.freed << le.mapped);
        return false;
    }

    if (slotId == header.firstSlot) {
        // If we are the inode, the anchored flag cannot be set yet.
        if (entries[fileno].anchored) {
            debugs(79, 7, "cannot add; extra anchor");
            return false;
        }

        // And there should have been some other slot for this entry to exist.
        if (le.more < 0) {
            debugs(79, 7, "cannot add; missing slots");
            return false;
        }

        return true;
    }

    // We are the continuation slice so the more field is reserved for us.
    if (le.more >= 0) {
        debugs(79, 7, "cannot add; foreign slot");
        return false;
    }

    return true;
}

/// handle freshly loaded (and validated) db slot header
void
Rock::Rebuild::useNewSlot(const SlotId slotId, const DbCellHeader &header)
{
    LoadingEntry &slice = entries[slotId];
    assert(!slice.freed); // we cannot free what was not loaded

    const cache_key *const key =
        reinterpret_cast<const cache_key*>(header.key);
    const sfileno fileno = sd->map->anchorIndexByKey(key);
    assert(0 <= fileno && fileno < dbEntryLimit);

    LoadingEntry &le = entries[fileno];
    debugs(47,9, "entry " << fileno << " state: " << le.state << ", inode: " <<
           header.firstSlot << ", size: " << header.payloadSize);

    switch (le.state) {

    case LoadingEntry::leEmpty: {
        startNewEntry(fileno, slotId, header);
        break;
    }

    case LoadingEntry::leLoading: {
        if (canAdd(fileno, slotId, header)) {
            addSlotToEntry(fileno, slotId, header);
        } else {
            // either the loading chain or this slot is stale;
            // be conservative and ignore both (and any future ones)
            le.state = LoadingEntry::leCorrupted;
            freeBadEntry(fileno, "duplicated");
            freeSlotIfIdle(slotId, slotId == header.firstSlot);
            ++counts.dupcount;
        }
        break;
    }

    case LoadingEntry::leLoaded: {
        // either the previously loaded chain or this slot is stale;
        // be conservative and ignore both (and any future ones)
        le.state = LoadingEntry::leCorrupted;
        sd->map->freeEntry(fileno); // may not be immediately successful
        freeSlotIfIdle(slotId, slotId == header.firstSlot);
        ++counts.dupcount;
        break;
    }

    case LoadingEntry::leCorrupted: {
        // previously seen slots messed things up so we must ignore this one
        freeSlotIfIdle(slotId, false);
        break;
    }

    case LoadingEntry::leIgnored: {
        // already replaced by a fresher or colliding from-network entry
        freeSlotIfIdle(slotId, false);
        break;
    }
    }
}

