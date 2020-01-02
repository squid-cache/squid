/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_STORE_MAP_H
#define SQUID_IPC_STORE_MAP_H

#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/Pointer.h"
#include "ipc/ReadWriteLock.h"
#include "sbuf/SBuf.h"
#include "store/forward.h"
#include "store_key_md5.h"

#include <functional>

namespace Ipc
{

typedef int32_t StoreMapSliceId;

/// a piece of Store entry, linked to other pieces, forming a chain
/// slices may be appended by writers while readers read the entry
class StoreMapSlice
{
public:
    typedef uint32_t Size;

    StoreMapSlice(): size(0), next(-1) {}
    StoreMapSlice(const StoreMapSlice &o) {
        size.exchange(o.size);
        next.exchange(o.next);
    }

    StoreMapSlice &operator =(const StoreMapSlice &o) {
        size.store(o.size);
        next.store(o.next);
        return *this;
    }

    /// restore default-constructed state
    void clear() { size = 0; next = -1; }

    std::atomic<Size> size; ///< slice contents size
    std::atomic<StoreMapSliceId> next; ///< ID of the next entry slice
};

/// Maintains shareable information about a StoreEntry as a whole.
/// An anchor points to one or more StoreEntry slices. This is the
/// only lockable part of shared StoreEntry information, providing
/// protection for all StoreEntry slices.
class StoreMapAnchor
{
public:
    StoreMapAnchor();

    /// store StoreEntry key and basics for an inode slot
    void set(const StoreEntry &anEntry, const cache_key *aKey = nullptr);
    /// load StoreEntry basics that were previously stored with set()
    void exportInto(StoreEntry &) const;

    void setKey(const cache_key *const aKey);
    bool sameKey(const cache_key *const aKey) const;

    /// undo the effects of set(), setKey(), etc., but keep locks and state
    void rewind();

    /* entry state may change immediately after calling these methods unless
     * the caller holds an appropriate lock */
    bool empty() const { return !key[0] && !key[1]; }
    bool reading() const { return lock.readers; }
    bool writing() const { return lock.writing; }
    bool complete() const { return !empty() && !writing(); }

public:
    mutable ReadWriteLock lock; ///< protects slot data below
    std::atomic<uint8_t> waitingToBeFreed; ///< may be accessed w/o a lock
    /// whether StoreMap::abortWriting() was called for a read-locked entry
    std::atomic<uint8_t> writerHalted;

    // fields marked with [app] can be modified when appending-while-reading
    // fields marked with [update] can be modified when updating-while-reading

    uint64_t key[2] = {0, 0}; ///< StoreEntry key

    // STORE_META_STD TLV field from StoreEntry
    struct Basics {
        void clear() {
            timestamp = 0;
            lastref = 0;
            expires = 0;
            lastmod = 0;
            swap_file_sz.store(0);
            refcount = 0;
            flags = 0;
        }
        time_t timestamp = 0;
        time_t lastref = 0;
        time_t expires = 0;
        time_t lastmod = 0;
        std::atomic<uint64_t> swap_file_sz; // [app]
        uint16_t refcount = 0;
        uint16_t flags = 0;
    } basics;

    /// where the chain of StoreEntry slices begins [app]
    std::atomic<StoreMapSliceId> start;

    /// where the updated chain prefix containing metadata/headers ends [update]
    /// if unset, this anchor points to a chain that was never updated
    std::atomic<StoreMapSliceId> splicingPoint;
};

/// an array of shareable Items
/// must be the last data member or, if used as a parent class, the last parent
template <class C>
class StoreMapItems
{
public:
    typedef C Item;
    typedef Ipc::Mem::Owner< StoreMapItems<Item> > Owner;

    explicit StoreMapItems(const int aCapacity): capacity(aCapacity), items(aCapacity) {}

    size_t sharedMemorySize() const { return SharedMemorySize(capacity); }
    static size_t SharedMemorySize(const int aCapacity) { return sizeof(StoreMapItems<Item>) + aCapacity*sizeof(Item); }

    const int capacity; ///< total number of items
    Ipc::Mem::FlexibleArray<Item> items; ///< storage
};

/// StoreMapSlices indexed by their slice ID.
typedef StoreMapItems<StoreMapSlice> StoreMapSlices;

/// StoreMapAnchors (indexed by fileno) plus
/// sharing-safe basic housekeeping info about Store entries
class StoreMapAnchors
{
public:
    typedef Ipc::Mem::Owner< StoreMapAnchors > Owner;

    explicit StoreMapAnchors(const int aCapacity);

    size_t sharedMemorySize() const;
    static size_t SharedMemorySize(const int anAnchorLimit);

    std::atomic<int32_t> count; ///< current number of entries
    std::atomic<uint32_t> victim; ///< starting point for purge search
    const int capacity; ///< total number of anchors
    Ipc::Mem::FlexibleArray<StoreMapAnchor> items; ///< anchors storage
};
// TODO: Find an elegant way to use StoreMapItems in StoreMapAnchors

/// StoreMapAnchor positions, indexed by entry "name" (i.e., the entry key hash)
typedef StoreMapItems< std::atomic<sfileno> > StoreMapFileNos;

/// Aggregates information required for updating entry metadata and headers.
class StoreMapUpdate
{
public:
    /// During an update, the stored entry has two editions: stale and fresh.
    class Edition
    {
    public:
        Edition(): anchor(nullptr), fileNo(-1), name(-1), splicingPoint(-1) {}

        /// whether this entry edition is currently used/initialized
        explicit operator bool() const { return anchor; }

        StoreMapAnchor *anchor; ///< StoreMap::anchors[fileNo], for convenience/speed
        sfileno fileNo; ///< StoreMap::fileNos[name], for convenience/speed
        sfileno name; ///< StoreEntry position in StoreMap::fileNos, for swapping Editions

        /// the last slice in the chain still containing metadata/headers
        StoreMapSliceId splicingPoint;
    };

    explicit StoreMapUpdate(StoreEntry *anEntry);
    StoreMapUpdate(const StoreMapUpdate &other);
    ~StoreMapUpdate();

    StoreMapUpdate &operator =(const StoreMapUpdate &other) = delete;

    StoreEntry *entry; ///< the store entry being updated
    Edition stale; ///< old anchor and chain
    Edition fresh; ///< new anchor and the updated chain prefix
};

class StoreMapCleaner;

/// Manages shared Store index (e.g., locking/unlocking/freeing entries) using
/// StoreMapFileNos indexed by hashed entry keys (a.k.a. entry names),
/// StoreMapAnchors indexed by fileno, and
/// StoreMapSlices indexed by slice ID.
class StoreMap
{
public:
    typedef StoreMapFileNos FileNos;
    typedef StoreMapAnchor Anchor;
    typedef StoreMapAnchors Anchors;
    typedef sfileno AnchorId;
    typedef StoreMapSlice Slice;
    typedef StoreMapSlices Slices;
    typedef StoreMapSliceId SliceId;
    typedef StoreMapUpdate Update;

public:
    /// aggregates anchor and slice owners for Init() caller convenience
    class Owner
    {
    public:
        Owner();
        ~Owner();
        FileNos::Owner *fileNos;
        Anchors::Owner *anchors;
        Slices::Owner *slices;
    private:
        Owner(const Owner &); // not implemented
        Owner &operator =(const Owner &); // not implemented
    };

    /// initialize shared memory
    static Owner *Init(const SBuf &path, const int slotLimit);

    StoreMap(const SBuf &aPath);

    /// computes map entry anchor position for a given entry key
    sfileno fileNoByKey(const cache_key *const key) const;

    /// Like strcmp(mapped, new), but for store entry versions/timestamps.
    /// Returns +2 if the mapped entry does not exist; -1/0/+1 otherwise.
    /// Comparison may be inaccurate unless the caller is a lock holder.
    int compareVersions(const sfileno oldFileno, time_t newVersion) const;

    /// finds, locks, and returns an anchor for an empty key position,
    /// erasing the old entry (if any)
    Anchor *openForWriting(const cache_key *const key, sfileno &fileno);
    /// locks and returns an anchor for the empty fileno position; if
    /// overwriteExisting is false and the position is not empty, returns nil
    Anchor *openForWritingAt(sfileno fileno, bool overwriteExisting = true);
    /// restrict opened for writing entry to appending operations; allow reads
    void startAppending(const sfileno fileno);
    /// successfully finish creating or updating the entry at fileno pos
    void closeForWriting(const sfileno fileno);
    /// stop writing (or updating) the locked entry and start reading it
    void switchWritingToReading(const sfileno fileno);
    /// unlock and "forget" openForWriting entry, making it Empty again
    /// this call does not free entry slices so the caller has to do that
    void forgetWritingEntry(const sfileno fileno);

    /// finds and locks the Update entry for an exclusive metadata update
    bool openForUpdating(Update &update, sfileno fileNoHint);
    /// makes updated info available to others, unlocks, and cleans up
    void closeForUpdating(Update &update);
    /// undoes partial update, unlocks, and cleans up
    void abortUpdating(Update &update);

    /// only works on locked entries; returns nil unless the slice is readable
    const Anchor *peekAtReader(const sfileno fileno) const;

    /// only works on locked entries; returns the corresponding Anchor
    const Anchor &peekAtEntry(const sfileno fileno) const;

    /// free the entry if possible or mark it as waiting to be freed if not
    /// \returns whether the entry was neither empty nor marked
    bool freeEntry(const sfileno);
    /// free the entry if possible or mark it as waiting to be freed if not
    /// does nothing if we cannot check that the key matches the cached entry
    void freeEntryByKey(const cache_key *const key);

    /// whether the entry with the given key exists and was marked as
    /// "waiting to be freed" some time ago
    bool markedForDeletion(const cache_key *const);

    /// whether the index contains a valid readable entry with the given key
    bool hasReadableEntry(const cache_key *const);

    /// opens entry (identified by key) for reading, increments read level
    const Anchor *openForReading(const cache_key *const key, sfileno &fileno);
    /// opens entry (identified by sfileno) for reading, increments read level
    const Anchor *openForReadingAt(const sfileno fileno);
    /// closes open entry after reading, decrements read level
    void closeForReading(const sfileno fileno);

    /// writeable slice within an entry chain created by openForWriting()
    Slice &writeableSlice(const AnchorId anchorId, const SliceId sliceId);
    /// readable slice within an entry chain opened by openForReading()
    const Slice &readableSlice(const AnchorId anchorId, const SliceId sliceId) const;
    /// writeable anchor for the entry created by openForWriting()
    Anchor &writeableEntry(const AnchorId anchorId);
    /// readable anchor for the entry created by openForReading()
    const Anchor &readableEntry(const AnchorId anchorId) const;

    /// prepare a chain-unaffiliated slice for being added to an entry chain
    void prepFreeSlice(const SliceId sliceId);

    /// Returns the ID of the entry slice containing n-th byte or
    /// a negative ID if the entry does not store that many bytes (yet).
    /// Requires a read lock.
    SliceId sliceContaining(const sfileno fileno, const uint64_t nth) const;

    /// stop writing the entry, freeing its slot for others to use if possible
    void abortWriting(const sfileno fileno);

    /// either finds and frees an entry with at least 1 slice or returns false
    bool purgeOne();

    /// copies slice to its designated position
    void importSlice(const SliceId sliceId, const Slice &slice);

    /* SwapFilenMax limits the number of entries, but not slices or slots */
    bool validEntry(const int n) const; ///< whether n is a valid slice coordinate
    bool validSlice(const int n) const; ///< whether n is a valid slice coordinate
    int entryCount() const; ///< number of writeable and readable entries
    int entryLimit() const; ///< maximum entryCount() possible
    int sliceLimit() const; ///< maximum number of slices possible

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

    StoreMapCleaner *cleaner; ///< notified before a readable entry is freed

protected:
    const SBuf path; ///< cache_dir path or similar cache name; for logging
    Mem::Pointer<StoreMapFileNos> fileNos; ///< entry inodes (starting blocks)
    Mem::Pointer<StoreMapAnchors> anchors; ///< entry inodes (starting blocks)
    Mem::Pointer<StoreMapSlices> slices; ///< chained entry pieces positions

private:
    /// computes entry name (i.e., key hash) for a given entry key
    sfileno nameByKey(const cache_key *const key) const;
    /// computes anchor position for a given entry name
    sfileno fileNoByName(const sfileno name) const;
    void relocate(const sfileno name, const sfileno fileno);

    Anchor &anchorAt(const sfileno fileno);
    const Anchor &anchorAt(const sfileno fileno) const;
    Anchor &anchorByKey(const cache_key *const key);

    Slice &sliceAt(const SliceId sliceId);
    const Slice &sliceAt(const SliceId sliceId) const;
    Anchor *openForReading(Slice &s);
    bool openKeyless(Update::Edition &edition);
    void closeForUpdateFinal(Update &update);

    typedef std::function<bool (const sfileno name)> NameFilter; // a "name"-based test
    bool visitVictims(const NameFilter filter);

    void freeChain(const sfileno fileno, Anchor &inode, const bool keepLock);
    void freeChainAt(SliceId sliceId, const SliceId splicingPoint);
};

/// API for adjusting external state when dirty map slice is being freed
class StoreMapCleaner
{
public:
    virtual ~StoreMapCleaner() {}

    /// adjust slice-linked state before a locked Readable slice is erased
    virtual void noteFreeMapSlice(const StoreMapSliceId sliceId) = 0;
};

} // namespace Ipc

// We do not reuse FileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_IPC_STORE_MAP_H */

