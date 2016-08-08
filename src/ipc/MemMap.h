/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_STORE_MAP_H
#define SQUID_IPC_STORE_MAP_H

#include "Debug.h"
#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/Pointer.h"
#include "ipc/ReadWriteLock.h"
#include "sbuf/SBuf.h"
#include "store/forward.h"
#include "store_key_md5.h"
#include "tools.h"

#include <atomic>

namespace Ipc
{

// The MEMMAP_SLOT_KEY_SIZE and MEMMAP_SLOT_DATA_SIZE must be enough big
// to hold cached keys and data. Currently MemMap used only to store SSL
// shared session data which have keys of 32bytes and at most 10K data
#define MEMMAP_SLOT_KEY_SIZE 32
#define MEMMAP_SLOT_DATA_SIZE 10*1024

/// a MemMap basic element, holding basic shareable memory block info
class MemMapSlot
{
public:
    MemMapSlot();
    size_t size() const {return sizeof(MemMapSlot);}
    size_t keySize() const {return sizeof(key);}
    bool sameKey(const cache_key *const aKey) const;
    void set(const unsigned char *aKey, const void *block, size_t blockSize, time_t expire = 0);
    bool empty() const;
    bool reading() const { return lock.readers; }
    bool writing() const { return lock.writing; }

    std::atomic<uint8_t> waitingToBeFreed; ///< may be accessed w/o a lock
    mutable ReadWriteLock lock; ///< protects slot data below
    unsigned char key[MEMMAP_SLOT_KEY_SIZE]; ///< The entry key
    unsigned char p[MEMMAP_SLOT_DATA_SIZE]; ///< The memory block;
    size_t pSize;
    time_t expire;
};

class MemMapCleaner;

/// A map of MemMapSlots indexed by their keys, with read/write slot locking.
class MemMap
{
public:
    typedef MemMapSlot Slot;

    /// data shared across maps in different processes
    class Shared
    {
    public:
        Shared(const int aLimit, const size_t anExtrasSize);
        size_t sharedMemorySize() const;
        static size_t SharedMemorySize(const int limit, const size_t anExtrasSize);
        ~Shared();

        const int limit; ///< maximum number of map slots
        const size_t extrasSize; ///< size of slot extra data
        std::atomic<int> count; ///< current number of map slots
        Ipc::Mem::FlexibleArray<Slot> slots; ///< storage
    };

public:
    typedef Mem::Owner<Shared> Owner;

    /// initialize shared memory
    static Owner *Init(const char *const path, const int limit);

    MemMap(const char *const aPath);

    /// finds, locks and return a slot for an empty key position,
    /// erasing the old entry (if any)
    Slot *openForWriting(const cache_key *const key, sfileno &fileno);

    /// locks and returns a slot for the empty fileno position; if
    /// overwriteExisting is false and the position is not empty, returns nil
    Slot *openForWritingAt(sfileno fileno, bool overwriteExisting = true);

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

    bool full() const; ///< there are no empty slots left
    bool valid(const int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

    /// The cleaner MemMapCleaner::noteFreeMapSlot method called when a
    /// readable entry is freed.
    MemMapCleaner *cleaner;

protected:
    static Owner *Init(const char *const path, const int limit, const size_t extrasSize);

    const SBuf path; ///< cache_dir path, used for logging
    Mem::Pointer<Shared> shared;

private:
    int slotIndexByKey(const cache_key *const key) const;
    Slot &slotByKey(const cache_key *const key);

    Slot *openForReading(Slot &s);
    void abortWriting(const sfileno fileno);
    void freeIfNeeded(Slot &s);
    void freeLocked(Slot &s, bool keepLocked);
};

/// API for adjusting external state when dirty map slot is being freed
class MemMapCleaner
{
public:
    virtual ~MemMapCleaner() {}

    /// adjust slot-linked state before a locked Readable slot is erased
    virtual void noteFreeMapSlot(const sfileno slotId) = 0;
};

} // namespace Ipc

#endif /* SQUID_IPC_STORE_MAP_H */

