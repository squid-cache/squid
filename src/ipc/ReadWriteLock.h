/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IPC_READWRITELOCK_H
#define SQUID_SRC_IPC_READWRITELOCK_H

#include <atomic>
#include <iosfwd>

class StoreEntry;

namespace Ipc
{

class ReadWriteLockStats;

/// an atomic readers-writer or shared-exclusive lock suitable for maps/tables
/// Also supports reading-while-appending mode when readers and writer are
/// allowed to access the same locked object because the writer promisses
/// to only append new data and all size-related object properties are atomic.
class ReadWriteLock
{
public:
    ReadWriteLock() : readers(0), writing(false), appending(false), readLevel(0), writeLevel(0)
    {}

    bool lockShared(); ///< lock for reading or return false
    bool lockExclusive(); ///< lock for modification or return false
    bool lockHeaders(); ///< lock for [readable] metadata update or return false
    void unlockShared(); ///< undo successful sharedLock()
    void unlockExclusive(); ///< undo successful exclusiveLock()
    void unlockHeaders(); ///< undo successful lockHeaders()
    void switchExclusiveToShared(); ///< stop writing, start reading
    /// same as unlockShared() but also attempts to get a writer lock beforehand
    /// \returns whether the writer lock was acquired
    bool unlockSharedAndSwitchToExclusive();

    void startAppending(); ///< writer keeps its lock but also allows reading

    /// writer keeps its lock and disallows future readers
    /// \returns whether access became exclusive (i.e. no readers)
    /// \prec appending is true
    bool stopAppendingAndRestoreExclusive();

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

public:
    mutable std::atomic<uint32_t> readers; ///< number of reading users
    std::atomic<bool> writing; ///< there is a writing user (there can be at most 1)
    std::atomic<bool> appending; ///< the writer has promised to only append
    std::atomic_flag updating; ///< a reader is updating metadata/headers

private:
    bool finalizeExclusive();

    mutable std::atomic<uint32_t> readLevel; ///< number of users reading (or trying to)
    std::atomic<uint32_t> writeLevel; ///< number of users writing (or trying to write)
};

/// dumps approximate lock state (for debugging)
std::ostream &operator <<(std::ostream &, const ReadWriteLock &);

/// approximate stats of a set of ReadWriteLocks
class ReadWriteLockStats
{
public:
    ReadWriteLockStats();

    void dump(StoreEntry &e) const;

    int count; ///< the total number of locks
    int readable; ///< number of locks locked for reading
    int writeable; ///< number of locks locked for writing
    int idle; ///< number of unlocked locks
    int readers; ///< sum of lock.readers
    int writers; ///< sum of lock.writers
    int appenders; ///< number of appending writers
};

/// Same as assert(flag is set): The process assert()s if flag is not set.
/// Side effect: The unset flag becomes set just before we assert().
/// Needed because atomic_flag cannot be compared with a boolean.
void AssertFlagIsSet(std::atomic_flag &flag);

} // namespace Ipc

#endif /* SQUID_SRC_IPC_READWRITELOCK_H */

