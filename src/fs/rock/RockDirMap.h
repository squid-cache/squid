#ifndef SQUID_FS_ROCK_DIR_MAP_H
#define SQUID_FS_ROCK_DIR_MAP_H

#include "ipc/AtomicWord.h"
#include "ipc/SharedMemory.h"

namespace Rock {

/// \ingroup Rock
/// map of used db slots indexed by sfileno
class DirMap
{
public:
    DirMap(const int id, const int limit); ///< create a new shared DirMap
    DirMap(const int id); ///< open an existing shared DirMap

    bool full() const; ///< there are no empty slots left
    bool has(int n) const; ///< whether slot n is occupied
    bool valid(int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    void use(int n); ///< mark slot n as used
    void clear(int n); ///< mark slot n as unused
    int useNext(); ///< finds and uses an empty slot, returning its coordinate

    static int AbsoluteEntryLimit(); ///< maximum entryLimit() possible

private:
    int findNext() const;

    static int SharedSize(const int limit);

    SharedMemory shm; ///< shared memory segment

    typedef AtomicWordT<uint8_t> Slot;
    struct Shared {
        Shared(const int aLimit);

        /// unreliable next empty slot suggestion #1 (clear based)
        mutable AtomicWord hintPast;
        ///< unreliable next empty slot suggestion #2 (scan based)
        mutable AtomicWord hintNext;

        AtomicWord limit; ///< maximum number of map slots
        AtomicWord count; ///< current number of map slots

        Slot slots[]; ///< slots storage
    };
    Shared *shared; ///< pointer to shared memory
};

} // namespace Rock

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

#endif /* SQUID_FS_ROCK_DIR_MAP_H */
