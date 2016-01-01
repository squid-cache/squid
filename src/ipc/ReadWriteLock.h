/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_READ_WRITE_LOCK_H
#define SQUID_IPC_READ_WRITE_LOCK_H

#include "ipc/AtomicWord.h"

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
    // default constructor is OK because of shared memory zero-initialization

    bool lockShared(); ///< lock for reading or return false
    bool lockExclusive(); ///< lock for modification or return false
    void unlockShared(); ///< undo successful sharedLock()
    void unlockExclusive(); ///< undo successful exclusiveLock()
    void switchExclusiveToShared(); ///< stop writing, start reading

    void startAppending(); ///< writer keeps its lock but also allows reading

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

public:
    mutable Atomic::Word readers; ///< number of reading users
    Atomic::Word writing; ///< there is a writing user (there can be at most 1)
    Atomic::Word appending; ///< the writer has promissed to only append

private:
    mutable Atomic::Word readLevel; ///< number of users reading (or trying to)
    Atomic::Word writeLevel; ///< number of users writing (or trying to write)
};

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

} // namespace Ipc

#endif /* SQUID_IPC_READ_WRITE_LOCK_H */

