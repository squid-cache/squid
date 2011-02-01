#ifndef SQUID_FS_ROCK_DIR_MAP_H
#define SQUID_FS_ROCK_DIR_MAP_H

#include "ipc/AtomicWord.h"
#include "ipc/SharedMemory.h"

class StoreEntryBasics {
public:
    void set(const StoreEntry &from);

    /* START OF ON-DISK STORE_META_STD TLV field */
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    uint64_t swap_file_sz;
    u_short refcount;
    u_short flags;
    /* END OF ON-DISK STORE_META_STD */
};

namespace Rock {

/// \ingroup Rock
/// map of used db slots indexed by sfileno
class DirMap
{
public:
    DirMap(const char *const aPath, const int limit); ///< create a new shared DirMap
    DirMap(const char *const aPath); ///< open an existing shared DirMap

    /// start writing a new entry
    StoreEntryBasics *openForWriting(const cache_key *const key, sfileno &fileno);
    /// finish writing a new entry
    void closeForWriting(const sfileno fileno);

    /// mark slot as waiting to be freed, will be freed when no one uses it
    bool free(const sfileno fileno);

    /// open slot for reading, increments read level
    const StoreEntryBasics *openForReading(const cache_key *const key, sfileno &fileno);
    /// open slot for reading, increments read level
    const StoreEntryBasics *openForReadingAt(const sfileno fileno);
    /// close slot after reading, decrements read level
    void closeForReading(const sfileno fileno);

    bool full() const; ///< there are no empty slots left
    bool valid(int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    static int AbsoluteEntryLimit(); ///< maximum entryLimit() possible

private:
    struct Slot {
        enum {
            Empty,
            Writing,
            Usable,
            WaitingToBeFreed,
            Freeing
        };

        void setKey(const cache_key *const aKey);
        bool checkKey(const cache_key *const aKey) const;

        AtomicWordT<uint8_t> state; ///< slot state
        AtomicWord readLevel; ///< read level
        AtomicWordT<uint64_t> key[2]; ///< MD5 entry key
        StoreEntryBasics seBasics; ///< basic store entry data
    };

    struct Shared {
        Shared(const int aLimit);

        const AtomicWord limit; ///< maximum number of map slots
        AtomicWord count; ///< current number of map slots

        Slot slots[]; ///< slots storage
    };

    int slotIdx(const cache_key *const key) const;
    Slot &slot(const cache_key *const key);
    const StoreEntryBasics *openForReading(Slot &s);
    void freeIfNeeded(Slot &s);
    String sharedMemoryName();

    static int SharedSize(const int limit);

    const String path; ///< cache_dir path, used for logging
    SharedMemory shm; ///< shared memory segment
    Shared *shared; ///< pointer to shared memory
};

} // namespace Rock

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_FS_ROCK_DIR_MAP_H */
