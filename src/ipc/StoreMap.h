#ifndef SQUID_IPC_STORE_MAP_H
#define SQUID_IPC_STORE_MAP_H

#include "ipc/ReadWriteLock.h"
#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/Pointer.h"
#include "typedefs.h"

namespace Ipc
{

/// a StoreMap element, holding basic shareable StoreEntry info
class StoreMapSlot
{
public:
    StoreMapSlot();

    /// store StoreEntry key and basics
    void set(const StoreEntry &anEntry);

    void setKey(const cache_key *const aKey);
    bool sameKey(const cache_key *const aKey) const;

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

    /// possible persistent states
    typedef enum {
        Empty, ///< ready for writing, with nothing of value
        Writeable, ///< transitions from Empty to Readable
        Readable, ///< ready for reading
    } State;
    State state; ///< current state
};

class StoreMapCleaner;

/// map of StoreMapSlots indexed by their keys, with read/write slot locking
/// kids extend to store custom data
class StoreMap
{
public:
    typedef StoreMapSlot Slot;

    /// data shared across maps in different processes
    class Shared
    {
    public:
        Shared(const int aLimit, const size_t anExtrasSize);
        size_t sharedMemorySize() const;
        static size_t SharedMemorySize(const int limit, const size_t anExtrasSize);

        const int limit; ///< maximum number of map slots
        const size_t extrasSize; ///< size of slot extra data
        Atomic::Word count; ///< current number of map slots
        Ipc::Mem::FlexibleArray<Slot> slots; ///< slots storage
    };

public:
    typedef Mem::Owner<Shared> Owner;

    /// initialize shared memory
    static Owner *Init(const char *const path, const int limit);

    StoreMap(const char *const aPath);

    /// finds, reservers space for writing a new entry or returns nil
    Slot *openForWriting(const cache_key *const key, sfileno &fileno);
    /// successfully finish writing the entry
    void closeForWriting(const sfileno fileno, bool lockForReading = false);

    /// only works on locked entries; returns nil unless the slot is readable
    const Slot *peekAtReader(const sfileno fileno) const;

    /// mark the slot as waiting to be freed and, if possible, free it
    void free(const sfileno fileno);

    /// open slot for reading, increments read level
    const Slot *openForReading(const cache_key *const key, sfileno &fileno);
    /// open slot for reading, increments read level
    const Slot *openForReadingAt(const sfileno fileno);
    /// close slot after reading, decrements read level
    void closeForReading(const sfileno fileno);

    /// called by lock holder to terminate either slot writing or reading
    void abortIo(const sfileno fileno);

    bool full() const; ///< there are no empty slots left
    bool valid(const int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

    StoreMapCleaner *cleaner; ///< notified before a readable entry is freed

protected:
    static Owner *Init(const char *const path, const int limit, const size_t extrasSize);

    const String path; ///< cache_dir path, used for logging
    Mem::Pointer<Shared> shared;

private:
    int slotIndexByKey(const cache_key *const key) const;
    Slot &slotByKey(const cache_key *const key);

    Slot *openForReading(Slot &s);
    void abortWriting(const sfileno fileno);
    void freeIfNeeded(Slot &s);
    void freeLocked(Slot &s, bool keepLocked);
};

/// StoreMap with extra slot data
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

/// API for adjusting external state when dirty map slot is being freed
class StoreMapCleaner
{
public:
    virtual ~StoreMapCleaner() {}

    /// adjust slot-linked state before a locked Readable slot is erased
    virtual void cleanReadable(const sfileno fileno) = 0;
};

// StoreMapWithExtras implementation

template <class ExtrasT>
StoreMap::Owner *
StoreMapWithExtras<ExtrasT>::Init(const char *const path, const int limit)
{
    return StoreMap::Init(path, limit, sizeof(Extras));
}

template <class ExtrasT>
StoreMapWithExtras<ExtrasT>::StoreMapWithExtras(const char *const path):
        StoreMap(path)
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
