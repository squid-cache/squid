#ifndef SQUID_FS_ROCK_DIR_MAP_H
#define SQUID_FS_ROCK_DIR_MAP_H

#include "ipc/AtomicWord.h"
#include "ipc/SharedMemory.h"

class StoreEntryBasics {
public:
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
    DirMap(const int id, const int limit); ///< create a new shared DirMap
    DirMap(const int id); ///< open an existing shared DirMap

    /// start adding a new entry
    StoreEntryBasics *add(const cache_key *const key);
    /// start adding a new entry, with fileno check
    StoreEntryBasics *add(const cache_key *const key, const sfileno fileno);
    /// finish adding a new entry
    void added(const cache_key *const key);

    /// mark slot as waiting to be freed, will be freed when no one uses it
    bool free(const cache_key *const key);

    /// open slot for reading, increments read level
    const StoreEntryBasics *open(const cache_key *const key, sfileno &fileno);
    /// close slot after reading, decrements read level
    void close(const cache_key *const key);

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
    bool free(const sfileno fileno);
    const StoreEntryBasics *open(const sfileno fileno);
    void freeIfNeeded(Slot &s);

    static int SharedSize(const int limit);

    SharedMemory shm; ///< shared memory segment
    Shared *shared; ///< pointer to shared memory
};

} // namespace Rock

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_FS_ROCK_DIR_MAP_H */
