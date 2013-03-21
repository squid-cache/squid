#ifndef SQUID_IPC_STORE_MAP_H
#define SQUID_IPC_STORE_MAP_H

#include "ipc/ReadWriteLock.h"
#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/Pointer.h"
#include "typedefs.h"

namespace Ipc
{

typedef int32_t StoreMapSliceId;

/// a piece of Store entry, linked to other pieces, forming a chain
class StoreMapSlice
{
public:
    StoreMapSlice(): next(-1), size(0) {}

    StoreMapSliceId next; ///< ID of the next slice occupied by the entry
    uint32_t size; ///< slice contents size
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
    void set(const StoreEntry &anEntry);

    void setKey(const cache_key *const aKey);
    bool sameKey(const cache_key *const aKey) const;

    /// undo the effects of set(), setKey(), etc., but keep locks and state
    void rewind();

public:
    mutable ReadWriteLock lock; ///< protects slot data below
    Atomic::WordT<uint8_t> waitingToBeFreed; ///< may be accessed w/o a lock

    uint64_t key[2]; ///< StoreEntry key

    // STORE_META_STD TLV field from StoreEntry
    struct Basics {
        time_t timestamp;
        time_t lastref;
        time_t expires;
        time_t lastmod;
        uint64_t swap_file_sz;
        uint16_t refcount;
        uint16_t flags;
    } basics;

    StoreMapSliceId start; ///< where the chain of StoreEntry slices begins

    /// possible persistent states
    typedef enum {
        Empty, ///< ready for writing, with nothing of value
        Writeable, ///< transitions from Empty to Readable
        Readable, ///< ready for reading
    } State;
    State state; ///< current state
};

/// A hack to allocate one shared array for both anchors and slices.
/// Anchors are indexed by store entry ID and are independent from each other.
/// Slices are indexed by slice IDs and form entry chains using slice.next.
class StoreMapSlot {
public:
    StoreMapAnchor anchor; ///< information about store entry as a whole
    StoreMapSlice slice; ///< information about one stored entry piece
};

class StoreMapCleaner;

/// map of StoreMapSlots indexed by their keys, with read/write slice locking
/// kids extend to store custom data
class StoreMap
{
public:
    typedef StoreMapAnchor Anchor;
    typedef sfileno AnchorId;
    typedef StoreMapSlice Slice;
    typedef StoreMapSliceId SliceId;

    /// data shared across maps in different processes
    class Shared
    {
    public:
        Shared(const int aLimit, const size_t anExtrasSize);
        size_t sharedMemorySize() const;
        static size_t SharedMemorySize(const int limit, const size_t anExtrasSize);

        const int limit; ///< maximum number of store entries
        const size_t extrasSize; ///< size of slice extra data
        Atomic::Word count; ///< current number of entries
        Atomic::WordT<sfileno> victim; ///< starting point for purge search
        Ipc::Mem::FlexibleArray<StoreMapSlot> slots; ///< storage
    };

public:
    typedef Mem::Owner<Shared> Owner;

    /// initialize shared memory
    static Owner *Init(const char *const path, const int limit);

    StoreMap(const char *const aPath);

    /// computes map entry position for a given entry key
    sfileno anchorIndexByKey(const cache_key *const key) const;

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
    /// successfully finish creating or updating the entry at fileno pos
    void closeForWriting(const sfileno fileno, bool lockForReading = false);
    /// unlock and "forget" openForWriting entry, making it Empty again
    /// this call does not free entry slices so the caller has to do that
    void forgetWritingEntry(const sfileno fileno);

    /// only works on locked entries; returns nil unless the slice is readable
    const Anchor *peekAtReader(const sfileno fileno) const;

    /// if possible, free the entry and return true
    /// otherwise mark it as waiting to be freed and return false
    void freeEntry(const sfileno fileno);

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

    /// called by lock holder to terminate either slice writing or reading
    void abortIo(const sfileno fileno);

    /// finds an unlocked entry and frees it or returns false
    bool purgeOne();

    /// copies slice to its designated position
    void importSlice(const SliceId sliceId, const Slice &slice);

    bool full() const; ///< there are no empty slices left; XXX: remove as unused?
    bool valid(const int n) const; ///< whether n is a valid slice coordinate
    int entryCount() const; ///< number of writeable and readable entries
    int entryLimit() const; ///< maximum entryCount() possible

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

    StoreMapCleaner *cleaner; ///< notified before a readable entry is freed

protected:
    static Owner *Init(const char *const path, const int limit, const size_t extrasSize);

    const String path; ///< cache_dir path, used for logging
    Mem::Pointer<Shared> shared;

private:
    Anchor &anchorByKey(const cache_key *const key);

    Anchor *openForReading(Slice &s);
    void abortWriting(const sfileno fileno);

    void freeChain(const sfileno fileno, Anchor &inode, const bool keepLock);
};

/// StoreMap with extra slice data
/// Note: ExtrasT must be POD, it is initialized with zeroes, no
/// constructors or destructors are called
template <class ExtrasT>
class StoreMapWithExtras: public StoreMap
{
public:
    typedef ExtrasT Extras;

    /// initialize shared memory
    static Owner *Init(const char *const path, const int limit);

    StoreMapWithExtras(const char *const path);

    /// write access to the extras; call openForWriting() first!
    ExtrasT &extras(const sfileno fileno);
    /// read-only access to the extras; call openForReading() first!
    const ExtrasT &extras(const sfileno fileno) const;

protected:

    ExtrasT *sharedExtras; ///< pointer to extras in shared memory
};

/// API for adjusting external state when dirty map slice is being freed
class StoreMapCleaner
{
public:
    virtual ~StoreMapCleaner() {}

    /// adjust slice-linked state before a locked Readable slice is erased
    virtual void noteFreeMapSlice(const sfileno sliceId) = 0;
};

// StoreMapWithExtras implementation

template <class ExtrasT>
StoreMap::Owner *
StoreMapWithExtras<ExtrasT>::Init(const char *const path, const int limit)
{
    return StoreMap::Init(path, limit, sizeof(Extras));
}

template <class ExtrasT>
StoreMapWithExtras<ExtrasT>::StoreMapWithExtras(const char *const aPath):
        StoreMap(aPath)
{
    const size_t sharedSizeWithoutExtras =
        Shared::SharedMemorySize(entryLimit(), 0);
    sharedExtras = reinterpret_cast<Extras *>(reinterpret_cast<char *>(shared.getRaw()) + sharedSizeWithoutExtras);
}

template <class ExtrasT>
ExtrasT &
StoreMapWithExtras<ExtrasT>::extras(const sfileno fileno)
{
    return const_cast<ExtrasT &>(const_cast<const StoreMapWithExtras *>(this)->extras(fileno));
}

template <class ExtrasT>
const ExtrasT &
StoreMapWithExtras<ExtrasT>::extras(const sfileno fileno) const
{
    assert(sharedExtras);
    assert(valid(fileno));
    return sharedExtras[fileno];
}

} // namespace Ipc

// We do not reuse FileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_IPC_STORE_MAP_H */
