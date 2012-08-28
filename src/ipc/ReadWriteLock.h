#ifndef SQUID_IPC_READ_WRITE_LOCK_H
#define SQUID_IPC_READ_WRITE_LOCK_H

#include "ipc/AtomicWord.h"

class StoreEntry;

namespace Ipc
{

class ReadWriteLockStats;

/// an atomic readers-writer or shared-exclusive lock suitable for maps/tables
class ReadWriteLock
{
public:
    // default constructor is OK because of shared memory zero-initialization

    bool lockShared(); ///< lock for reading or return false
    bool lockExclusive(); ///< lock for modification or return false
    void unlockShared(); ///< undo successful sharedLock()
    void unlockExclusive(); ///< undo successful exclusiveLock()
    void switchExclusiveToShared(); ///< stop writing, start reading

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

public:
    mutable Atomic::Word readers; ///< number of users trying to read
    Atomic::Word writers; ///< number of writers trying to modify protected data
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
};

} // namespace Ipc

#endif /* SQUID_IPC_READ_WRITE_LOCK_H */
