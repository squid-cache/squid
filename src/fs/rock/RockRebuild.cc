/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "debug/Messages.h"
#include "fs/rock/RockDbCell.h"
#include "fs/rock/RockRebuild.h"
#include "fs/rock/RockSwapDir.h"
#include "fs_io.h"
#include "globals.h"
#include "md5.h"
#include "sbuf/Stream.h"
#include "Store.h"
#include "tools.h"

#include <array>
#include <cerrno>
#include <cstring>

CBDATA_NAMESPACED_CLASS_INIT(Rock, Rebuild);

/**
 \defgroup RockFsRebuild Rock Store Rebuild
 \ingroup Filesystems
 *
 \section RockFsRebuildOverview Overview
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
 *  iNode: The very first db slot in an entry slot chain. This slot contains
 *  at least the beginning of Store Entry metadata, but most 32KB inodes contain
 *  the entire metadata, HTTP headers, and HTTP body.
 \par
 *  Db slot: A db record containing a piece of a single store entry and linked
 *  to other slots with the same key and version fields, forming a chain.
 *  Slots are identified by their absolute position in the database file,
 *  which is naturally unique.
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

static bool
DoneLoading(const int64_t loadingPos, const int64_t dbSlotLimit)
{
    return loadingPos >= dbSlotLimit;
}

static bool
DoneValidating(const int64_t validationPos, const int64_t dbSlotLimit, const int64_t dbEntryLimit)
{
    // paranoid slot checking is only enabled with squid -S
    const auto extraWork = opt_store_doublecheck ? dbSlotLimit : 0;
    return validationPos >= (dbEntryLimit + extraWork);
}

/// low-level anti-padding storage class for LoadingEntry and LoadingSlot flags
class LoadingFlags
{
public:
    LoadingFlags(): state(0), anchored(0), mapped(0), finalized(0), freed(0) {}

    /* for LoadingEntry */
    uint8_t state:3;  ///< current entry state (one of the LoadingEntry::State values)
    uint8_t anchored:1;  ///< whether we loaded the inode slot for this entry

    /* for LoadingSlot */
    uint8_t mapped:1;  ///< whether the slot was added to a mapped entry
    uint8_t finalized:1;  ///< whether finalizeOrThrow() has scanned the slot
    uint8_t freed:1;  ///< whether the slot was given to the map as free space
};

/// smart StoreEntry-level info pointer (hides anti-padding LoadingParts arrays)
class LoadingEntry
{
public:
    LoadingEntry(const sfileno fileNo, LoadingParts &source);

    uint64_t &size; ///< payload seen so far
    uint32_t &version; ///< DbCellHeader::version to distinguish same-URL chains

    /// possible store entry states during index rebuild
    typedef enum { leEmpty = 0, leLoading, leLoaded, leCorrupted, leIgnored } State;

    /* LoadingFlags::state */
    State state() const { return static_cast<State>(flags.state); }
    void state(State aState) const { flags.state = aState; }

    /* LoadingFlags::anchored */
    bool anchored() const { return flags.anchored; }
    void anchored(const bool beAnchored) { flags.anchored = beAnchored; }

private:
    LoadingFlags &flags; ///< entry flags (see the above accessors) are ours
};

/// smart db slot-level info pointer (hides anti-padding LoadingParts arrays)
class LoadingSlot
{
public:
    LoadingSlot(const SlotId slotId, LoadingParts &source);

    /// another slot in some chain belonging to the same entry (unordered!)
    Ipc::StoreMapSliceId &more;

    /* LoadingFlags::mapped */
    bool mapped() const { return flags.mapped; }
    void mapped(const bool beMapped) { flags.mapped = beMapped; }

    /* LoadingFlags::finalized */
    bool finalized() const { return flags.finalized; }
    void finalized(const bool beFinalized) { flags.finalized = beFinalized; }

    /* LoadingFlags::freed */
    bool freed() const { return flags.freed; }
    void freed(const bool beFreed) { flags.freed = beFreed; }

    bool used() const { return freed() || mapped() || more != -1; }

private:
    LoadingFlags &flags; ///< slot flags (see the above accessors) are ours
};

/// information about store entries being loaded from disk (and their slots)
/// used for identifying partially stored/loaded entries
class LoadingParts
{
public:
    using Sizes = Ipc::StoreMapItems<uint64_t>;
    using Versions = Ipc::StoreMapItems<uint32_t>;
    using Mores = Ipc::StoreMapItems<Ipc::StoreMapSliceId>;
    using Flags = Ipc::StoreMapItems<LoadingFlags>;

    LoadingParts(const SwapDir &dir, const bool resuming);
    ~LoadingParts();

    // lacking copying/moving code and often too huge to copy
    LoadingParts(LoadingParts&&) = delete;

    Sizes &sizes() const { return *sizesOwner->object(); }
    Versions &versions() const { return *versionsOwner->object(); }
    Mores &mores() const { return *moresOwner->object(); }
    Flags &flags() const { return *flagsOwner->object(); }

private:
    /* Anti-padding storage. With millions of entries, padding matters! */

    /* indexed by sfileno */
    Sizes::Owner *sizesOwner; ///< LoadingEntry::size for all entries
    Versions::Owner *versionsOwner; ///< LoadingEntry::version for all entries

    /* indexed by SlotId */
    Mores::Owner *moresOwner; ///< LoadingSlot::more for all slots

    /* entry flags are indexed by sfileno; slot flags -- by SlotId */
    Flags::Owner *flagsOwner; ///< all LoadingEntry and LoadingSlot flags
};

} /* namespace Rock */

/* LoadingEntry */

Rock::LoadingEntry::LoadingEntry(const sfileno fileNo, LoadingParts &source):
    size(source.sizes().at(fileNo)),
    version(source.versions().at(fileNo)),
    flags(source.flags().at(fileNo))
{
}

/* LoadingSlot */

Rock::LoadingSlot::LoadingSlot(const SlotId slotId, LoadingParts &source):
    more(source.mores().at(slotId)),
    flags(source.flags().at(slotId))
{
}

/* LoadingParts */

template <class T>
inline typename T::Owner *
createOwner(const char *dirPath, const char *sfx, const int64_t limit, const bool resuming)
{
    auto id = Ipc::Mem::Segment::Name(SBuf(dirPath), sfx);
    return resuming ? Ipc::Mem::Owner<T>::Old(id.c_str()) : shm_new(T)(id.c_str(), limit);
}

Rock::LoadingParts::LoadingParts(const SwapDir &dir, const bool resuming):
    sizesOwner(createOwner<Sizes>(dir.path, "rebuild_sizes", dir.entryLimitActual(), resuming)),
    versionsOwner(createOwner<Versions>(dir.path, "rebuild_versions", dir.entryLimitActual(), resuming)),
    moresOwner(createOwner<Mores>(dir.path, "rebuild_mores", dir.slotLimitActual(), resuming)),
    flagsOwner(createOwner<Flags>(dir.path, "rebuild_flags", dir.slotLimitActual(), resuming))
{
    assert(sizes().capacity == versions().capacity); // every entry has both fields
    assert(sizes().capacity <= mores().capacity); // every entry needs slot(s)
    assert(mores().capacity == flags().capacity); // every slot needs a set of flags

    if (!resuming) {
        // other parts rely on shared memory segments being zero-initialized
        // TODO: refactor the next slot pointer to use 0 for nil values
        mores().fill(-1);
    }
}

Rock::LoadingParts::~LoadingParts()
{
    delete sizesOwner;
    delete versionsOwner;
    delete moresOwner;
    delete flagsOwner;
}

/* Rock::Rebuild::Stats */

SBuf
Rock::Rebuild::Stats::Path(const char *dirPath)
{
    return Ipc::Mem::Segment::Name(SBuf(dirPath), "rebuild_stats");
}

Ipc::Mem::Owner<Rock::Rebuild::Stats>*
Rock::Rebuild::Stats::Init(const SwapDir &dir)
{
    return shm_new(Stats)(Path(dir.path).c_str());
}

bool
Rock::Rebuild::Stats::completed(const SwapDir &dir) const
{
    return DoneLoading(counts.scancount, dir.slotLimitActual()) &&
           DoneValidating(counts.validations, dir.slotLimitActual(), dir.entryLimitActual());
}

/* Rebuild */

bool
Rock::Rebuild::IsResponsible(const SwapDir &)
{
    // in SMP mode, only the disker is responsible for populating the map
    return !UsingSmp() || IamDiskProcess();
}

bool
Rock::Rebuild::Start(SwapDir &dir)
{
    if (!IsResponsible(dir)) {
        debugs(47, 2, "not responsible for indexing cache_dir #" <<
               dir.index << " from " << dir.filePath);
        return false;
    }

    const auto stats = shm_old(Rebuild::Stats)(Stats::Path(dir.path).c_str());
    if (stats->completed(dir)) {
        debugs(47, 2, "already indexed cache_dir #" <<
               dir.index << " from " << dir.filePath);
        return false;
    }

    AsyncJob::Start(new Rebuild(&dir, stats));
    return true;
}

Rock::Rebuild::Rebuild(SwapDir *dir, const Ipc::Mem::Pointer<Stats> &s): AsyncJob("Rock::Rebuild"),
    sd(dir),
    parts(nullptr),
    stats(s),
    dbSize(0),
    dbSlotSize(0),
    dbSlotLimit(0),
    dbEntryLimit(0),
    fd(-1),
    dbOffset(0),
    loadingPos(stats->counts.scancount),
    validationPos(stats->counts.validations),
    counts(stats->counts),
    resuming(stats->counts.started())
{
    assert(sd);
    dbSize = sd->diskOffsetLimit(); // we do not care about the trailer waste
    dbSlotSize = sd->slotSize;
    dbEntryLimit = sd->entryLimitActual();
    dbSlotLimit = sd->slotLimitActual();
    assert(dbEntryLimit <= dbSlotLimit);
    registerRunner();
}

Rock::Rebuild::~Rebuild()
{
    if (fd >= 0)
        file_close(fd);
    // normally, segments are used until the Squid instance quits,
    // but these indexing-only segments are no longer needed
    delete parts;
}

void
Rock::Rebuild::startShutdown()
{
    mustStop("startShutdown");
}

/// prepares and initiates entry loading sequence
void
Rock::Rebuild::start()
{
    assert(IsResponsible(*sd));

    if (!resuming) {
        debugs(47, Important(18), "Loading cache_dir #" << sd->index <<
               " from " << sd->filePath);
    } else {
        debugs(47, Important(63), "Resuming indexing cache_dir #" << sd->index <<
               " from " << sd->filePath << ':' << progressDescription());
    }

    fd = file_open(sd->filePath, O_RDONLY | O_BINARY);
    if (fd < 0)
        failure("cannot open db", errno);

    char hdrBuf[SwapDir::HeaderSize];
    if (read(fd, hdrBuf, sizeof(hdrBuf)) != SwapDir::HeaderSize)
        failure("cannot read db header", errno);

    // slot prefix of SM_PAGE_SIZE should fit both core entry header and ours
    assert(sizeof(DbCellHeader) < SM_PAGE_SIZE);
    buf.init(SM_PAGE_SIZE, SM_PAGE_SIZE);

    dbOffset = SwapDir::HeaderSize + loadingPos * dbSlotSize;

    assert(!parts);
    parts = new LoadingParts(*sd, resuming);

    counts.updateStartTime(current_time);

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
Rock::Rebuild::doneLoading() const
{
    return DoneLoading(loadingPos, dbSlotLimit);
}

bool
Rock::Rebuild::doneValidating() const
{
    return DoneValidating(validationPos, dbSlotLimit, dbEntryLimit);
}

bool
Rock::Rebuild::doneAll() const
{
    return doneLoading() && doneValidating() && AsyncJob::doneAll();
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
    if (!doneLoading())
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

    int64_t loaded = 0;
    while (!doneLoading()) {
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
            debugs(47, 5, "pausing after " << loaded << " entries in " <<
                   elapsedMsec << "ms; " << (elapsedMsec/loaded) << "ms per entry");
            break;
        }
    }
}

Rock::LoadingEntry
Rock::Rebuild::loadingEntry(const sfileno fileNo)
{
    Must(0 <= fileNo && fileNo < dbEntryLimit);
    return LoadingEntry(fileNo, *parts);
}

Rock::LoadingSlot
Rock::Rebuild::loadingSlot(const SlotId slotId)
{
    Must(0 <= slotId && slotId < dbSlotLimit);
    Must(slotId <= loadingPos); // cannot look ahead
    return LoadingSlot(slotId, *parts);
}

void
Rock::Rebuild::loadOneSlot()
{
    debugs(47,5, sd->index << " slot " << loadingPos << " at " <<
           dbOffset << " <= " << dbSize);

    // increment before loadingPos to avoid getting stuck at a slot
    // in a case of crash
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
        freeUnusedSlot(slotId, true);
        return;
    }
    memcpy(&header, buf.content(), sizeof(header));
    if (header.empty()) {
        freeUnusedSlot(slotId, false);
        return;
    }
    if (!header.sane(dbSlotSize, dbSlotLimit)) {
        debugs(47, DBG_IMPORTANT, "WARNING: cache_dir[" << sd->index << "]: " <<
               "Ignoring malformed cache entry meta data at " << dbOffset);
        freeUnusedSlot(slotId, true);
        return;
    }
    buf.consume(sizeof(header)); // optimize to avoid memmove()

    useNewSlot(slotId, header);
}

/// whether the given slot buffer is likely to have nothing but zeros, as is
/// common to slots in pre-initialized (with zeros) db files
static bool
ZeroedSlot(const MemBuf &buf)
{
    // We could memcmp the entire buffer, but it is probably safe enough to test
    // a few bytes because even if we do not detect a corrupted entry, it is not
    // a big deal: Store::UnpackPrefix() rejects all-0s metadata prefix.
    static const std::array<char, 10> zeros = {};

    if (static_cast<size_t>(buf.contentSize()) < zeros.size())
        return false; // cannot be sure enough

    return memcmp(buf.content(), zeros.data(), zeros.size()) == 0;
}

/// parse StoreEntry basics and add them to the map, returning true on success
bool
Rock::Rebuild::importEntry(Ipc::StoreMapAnchor &anchor, const sfileno fileno, const DbCellHeader &header)
{
    cache_key key[SQUID_MD5_DIGEST_LENGTH];
    StoreEntry loadedE;
    const uint64_t knownSize = header.entrySize > 0 ?
                               header.entrySize : anchor.basics.swap_file_sz.load();

    if (ZeroedSlot(buf))
        return false;

    if (!storeRebuildParseEntry(buf, loadedE, key, counts, knownSize))
        return false;

    // the entry size may be unknown, but if it is known, it is authoritative

    debugs(47, 8, "importing basics for entry " << fileno <<
           " inode.entrySize: " << header.entrySize <<
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

    int64_t validated = 0;
    while (!doneValidating()) {
        // increment before validationPos to avoid getting stuck at a slot
        // in a case of crash
        ++counts.validations;
        if (validationPos < dbEntryLimit)
            validateOneEntry(validationPos);
        else
            validateOneSlot(validationPos - dbEntryLimit);
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

/// Either make the entry accessible to all or throw.
/// This method assumes it is called only when no more entry slots are expected.
void
Rock::Rebuild::finalizeOrThrow(const sfileno fileNo, LoadingEntry &le)
{
    // walk all map-linked slots, starting from inode, and mark each
    Ipc::StoreMapAnchor &anchor = sd->map->writeableEntry(fileNo);
    Must(le.size > 0); // paranoid
    uint64_t mappedSize = 0;
    SlotId slotId = anchor.start;
    while (slotId >= 0 && mappedSize < le.size) {
        LoadingSlot slot = loadingSlot(slotId); // throws if we have not loaded that slot
        Must(!slot.finalized()); // no loops or stealing from other entries
        Must(slot.mapped()); // all our slots should be in the sd->map
        Must(!slot.freed()); // all our slots should still be present
        slot.finalized(true);

        Ipc::StoreMapSlice &mapSlice = sd->map->writeableSlice(fileNo, slotId);
        Must(mapSlice.size > 0); // paranoid
        mappedSize += mapSlice.size;
        slotId = mapSlice.next;
    }
    /* no hodgepodge entries: one entry - one full chain and no leftovers */
    Must(slotId < 0);
    Must(mappedSize == le.size);

    if (!anchor.basics.swap_file_sz)
        anchor.basics.swap_file_sz = le.size;
    EBIT_SET(anchor.basics.flags, ENTRY_VALIDATED);
    le.state(LoadingEntry::leLoaded);
    sd->map->closeForWriting(fileNo);
    ++counts.objcount;
}

/// Either make the entry accessible to all or free it.
/// This method must only be called when no more entry slots are expected.
void
Rock::Rebuild::finalizeOrFree(const sfileno fileNo, LoadingEntry &le)
{
    try {
        finalizeOrThrow(fileNo, le);
    } catch (const std::exception &ex) {
        freeBadEntry(fileNo, ex.what());
    }
}

void
Rock::Rebuild::validateOneEntry(const sfileno fileNo)
{
    LoadingEntry entry = loadingEntry(fileNo);
    switch (entry.state()) {

    case LoadingEntry::leLoading:
        finalizeOrFree(fileNo, entry);
        break;

    case LoadingEntry::leEmpty: // no entry hashed to this position
    case LoadingEntry::leLoaded: // we have already unlocked this entry
    case LoadingEntry::leCorrupted: // we have already removed this entry
    case LoadingEntry::leIgnored: // we have already discarded this entry
        break;
    }
}

void
Rock::Rebuild::validateOneSlot(const SlotId slotId)
{
    const LoadingSlot slot = loadingSlot(slotId);
    // there should not be any unprocessed slots left
    Must(slot.freed() || (slot.mapped() && slot.finalized()));
}

/// Marks remaining bad entry slots as free and unlocks the entry. The map
/// cannot do this because Loading entries may have holes in the slots chain.
void
Rock::Rebuild::freeBadEntry(const sfileno fileno, const char *eDescription)
{
    debugs(47, 2, "cache_dir #" << sd->index << ' ' << eDescription <<
           " entry " << fileno << " is ignored during rebuild");

    LoadingEntry le = loadingEntry(fileno);
    le.state(LoadingEntry::leCorrupted);

    Ipc::StoreMapAnchor &anchor = sd->map->writeableEntry(fileno);
    assert(anchor.start < 0 || le.size > 0);
    for (SlotId slotId = anchor.start; slotId >= 0;) {
        const SlotId next = loadingSlot(slotId).more;
        freeSlot(slotId, true);
        slotId = next;
    }

    sd->map->forgetWritingEntry(fileno);
}

void
Rock::Rebuild::swanSong()
{
    debugs(47,3, "cache_dir #" << sd->index << " rebuild level: " <<
           StoreController::store_dirs_rebuilding);
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
    LoadingSlot slot = loadingSlot(slotId);
    assert(!slot.freed());
    slot.freed(true);

    if (invalid) {
        ++counts.invalid;
        //sd->unlink(fileno); leave garbage on disk, it should not hurt
    }

    Ipc::Mem::PageId pageId;
    pageId.pool = Ipc::Mem::PageStack::IdForSwapDirSpace(sd->index);
    pageId.number = slotId+1;
    sd->freeSlots->push(pageId);
}

/// freeSlot() for never-been-mapped slots
void
Rock::Rebuild::freeUnusedSlot(const SlotId slotId, const bool invalid)
{
    LoadingSlot slot = loadingSlot(slotId);
    // mapped slots must be freed via freeBadEntry() to keep the map in sync
    assert(!slot.mapped());
    freeSlot(slotId, invalid);
}

/// adds slot to the entry chain in the map
void
Rock::Rebuild::mapSlot(const SlotId slotId, const DbCellHeader &header)
{
    LoadingSlot slot = loadingSlot(slotId);
    assert(!slot.mapped());
    assert(!slot.freed());
    slot.mapped(true);

    Ipc::StoreMapSlice slice;
    slice.next = header.nextSlot;
    slice.size = header.payloadSize;
    sd->map->importSlice(slotId, slice);
}

template <class SlotIdType> // accommodates atomic and simple SlotIds.
void
Rock::Rebuild::chainSlots(SlotIdType &from, const SlotId to)
{
    LoadingSlot slot = loadingSlot(to);
    assert(slot.more < 0);
    slot.more = from; // may still be unset
    from = to;
}

/// adds slot to an existing entry chain; caller must check that the slot
/// belongs to the chain it is being added to
void
Rock::Rebuild::addSlotToEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header)
{
    LoadingEntry le = loadingEntry(fileno);
    Ipc::StoreMapAnchor &anchor = sd->map->writeableEntry(fileno);

    debugs(47,9, "adding " << slotId << " to entry " << fileno);
    // we do not need to preserve the order
    if (le.anchored()) {
        LoadingSlot inode = loadingSlot(anchor.start);
        chainSlots(inode.more, slotId);
    } else {
        chainSlots(anchor.start, slotId);
    }

    le.size += header.payloadSize; // must precede freeBadEntry() calls

    if (header.firstSlot == slotId) {
        debugs(47,5, "added inode");

        if (le.anchored()) { // we have already added another inode slot
            freeBadEntry(fileno, "inode conflict");
            ++counts.clashcount;
            return;
        }

        le.anchored(true);

        if (!importEntry(anchor, fileno, header)) {
            freeBadEntry(fileno, "corrupted metainfo");
            return;
        }

        // set total entry size and/or check it for consistency
        if (const uint64_t totalSize = header.entrySize) {
            assert(totalSize != static_cast<uint64_t>(-1));
            if (!anchor.basics.swap_file_sz) {
                anchor.basics.swap_file_sz = totalSize;
                assert(anchor.basics.swap_file_sz != static_cast<uint64_t>(-1));
            } else if (totalSize != anchor.basics.swap_file_sz) {
                freeBadEntry(fileno, "size mismatch");
                return;
            }
        }
    }

    const uint64_t totalSize = anchor.basics.swap_file_sz; // may be 0/unknown

    if (totalSize > 0 && le.size > totalSize) { // overflow
        debugs(47, 8, "overflow: " << le.size << " > " << totalSize);
        freeBadEntry(fileno, "overflowing");
        return;
    }

    mapSlot(slotId, header);
    if (totalSize > 0 && le.size == totalSize)
        finalizeOrFree(fileno, le); // entry is probably fully loaded now
}

/// initialize housekeeping information for a newly accepted entry
void
Rock::Rebuild::primeNewEntry(Ipc::StoreMap::Anchor &anchor, const sfileno fileno, const DbCellHeader &header)
{
    anchor.setKey(reinterpret_cast<const cache_key*>(header.key));
    assert(header.firstSlot >= 0);
    anchor.start = -1; // addSlotToEntry() will set it

    assert(anchor.basics.swap_file_sz != static_cast<uint64_t>(-1));

    LoadingEntry le = loadingEntry(fileno);
    le.state(LoadingEntry::leLoading);
    le.version = header.version;
    le.size = 0;
}

/// handle a slot from an entry that we have not seen before
void
Rock::Rebuild::startNewEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header)
{
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
        LoadingEntry le = loadingEntry(fileno);
        le.state(LoadingEntry::leIgnored);
        freeUnusedSlot(slotId, false);
    }
}

/// does the header belong to the fileno entry being loaded?
bool
Rock::Rebuild::sameEntry(const sfileno fileno, const DbCellHeader &header) const
{
    // Header updates always result in multi-start chains and often
    // result in multi-version chains so we can only compare the keys.
    const Ipc::StoreMap::Anchor &anchor = sd->map->writeableEntry(fileno);
    return anchor.sameKey(reinterpret_cast<const cache_key*>(header.key));
}

/// handle freshly loaded (and validated) db slot header
void
Rock::Rebuild::useNewSlot(const SlotId slotId, const DbCellHeader &header)
{
    const cache_key *const key =
        reinterpret_cast<const cache_key*>(header.key);
    const sfileno fileno = sd->map->fileNoByKey(key);
    assert(0 <= fileno && fileno < dbEntryLimit);

    LoadingEntry le = loadingEntry(fileno);
    debugs(47,9, "entry " << fileno << " state: " << le.state() << ", inode: " <<
           header.firstSlot << ", size: " << header.payloadSize);

    switch (le.state()) {

    case LoadingEntry::leEmpty: {
        startNewEntry(fileno, slotId, header);
        break;
    }

    case LoadingEntry::leLoading: {
        if (sameEntry(fileno, header)) {
            addSlotToEntry(fileno, slotId, header); // may fail
        } else {
            // either the loading chain or this slot is stale;
            // be conservative and ignore both (and any future ones)
            freeBadEntry(fileno, "duplicated");
            freeUnusedSlot(slotId, true);
            ++counts.dupcount;
        }
        break;
    }

    case LoadingEntry::leLoaded: {
        // either the previously loaded chain or this slot is stale;
        // be conservative and ignore both (and any future ones)
        le.state(LoadingEntry::leCorrupted);
        sd->map->freeEntry(fileno); // may not be immediately successful
        freeUnusedSlot(slotId, true);
        ++counts.dupcount;
        break;
    }

    case LoadingEntry::leCorrupted: {
        // previously seen slots messed things up so we must ignore this one
        freeUnusedSlot(slotId, true);
        break;
    }

    case LoadingEntry::leIgnored: {
        // already replaced by a fresher or colliding from-network entry
        freeUnusedSlot(slotId, false);
        break;
    }
    }
}

SBuf
Rock::Rebuild::progressDescription() const
{
    SBufStream str;

    str << Debug::Extra << "slots loaded: " << Progress(loadingPos, dbSlotLimit);

    const auto validatingEntries = validationPos < dbEntryLimit;
    const auto entriesValidated = validatingEntries ? validationPos : dbEntryLimit;
    str << Debug::Extra << "entries validated: " << Progress(entriesValidated, dbEntryLimit);
    if (opt_store_doublecheck) {
        const auto slotsValidated = validatingEntries ? 0 : (validationPos - dbEntryLimit);
        str << Debug::Extra << "slots validated: " << Progress(slotsValidated, dbSlotLimit);
    }

    return str.buf();
}

