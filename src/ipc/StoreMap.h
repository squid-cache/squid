#ifndef SQUID_IPC_STORE_MAP_H
#define SQUID_IPC_STORE_MAP_H

#include "ipc/ReadWriteLock.h"
#include "ipc/mem/Segment.h"
#include "typedefs.h"

namespace Ipc {

/// a StoreMap element, holding basic shareable StoreEntry info
class StoreMapSlot {
public:
    StoreMapSlot();

    /// store StoreEntry key and basics
    void set(const StoreEntry &anEntry);

    void setKey(const cache_key *const aKey);
    bool sameKey(const cache_key *const aKey) const;

public:
    mutable ReadWriteLock lock; ///< protects slot data below
    AtomicWordT<uint8_t> waitingToBeFreed; ///< may be accessed w/o a lock

    uint64_t key[2]; ///< StoreEntry key

    // STORE_META_STD TLV field from StoreEntry
    struct Basics {
        time_t timestamp;
        time_t lastref;
        time_t expires;
        time_t lastmod;
        uint64_t swap_file_sz;
        u_short refcount;
        u_short flags;
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

    StoreMap(const char *const aPath, const int limit, size_t sharedSizeExtra); ///< create a new shared StoreMap
    explicit StoreMap(const char *const aPath); ///< open an existing shared StoreMap

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
    bool valid(int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

    StoreMapCleaner *cleaner; ///< notified before a readable entry is freed

protected:
    class Shared {
    public:
        static size_t MemSize(int limit);

        Shared(const int aLimit);

        const AtomicWord limit; ///< maximum number of map slots
        AtomicWord count; ///< current number of map slots

        Slot slots[]; ///< slots storage
    };

protected:
    const String path; ///< cache_dir path, used for logging
    Ipc::Mem::Segment shm; ///< shared memory segment

private:
    int slotIndexByKey(const cache_key *const key) const;
    Slot &slotByKey(const cache_key *const key);

	Slot *openForReading(Slot &s);
    void abortWriting(const sfileno fileno);
    void freeIfNeeded(Slot &s);
    void freeLocked(Slot &s, bool keepLocked);
    String sharedMemoryName();

    Shared *shared; ///< pointer to shared memory
};

/// API for adjusting external state when dirty map slot is being freed
class StoreMapCleaner
{
public:
    virtual ~StoreMapCleaner() {}

    /// adjust slot-linked state before a locked Readable slot is erased
    virtual void cleanReadable(const sfileno fileno) = 0;
};


} // namespace Ipc

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_IPC_STORE_MAP_H */
