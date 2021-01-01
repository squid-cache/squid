/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/ReadWriteLock.h"
#include "Store.h"

void Ipc::AssertFlagIsSet(std::atomic_flag &flag)
{
    // If the flag was false, then we set it to true and assert. A true flag
    // may help keep other processes away from this broken entry.
    // Otherwise, we just set an already set flag, which is probably a no-op.
    assert(flag.test_and_set(std::memory_order_relaxed));
}

bool
Ipc::ReadWriteLock::lockShared()
{
    ++readLevel; // this locks "new" writers out
    if (!writeLevel || appending) { // nobody is writing, or sharing is OK
        ++readers;
        return true;
    }
    --readLevel;
    return false;
}

bool
Ipc::ReadWriteLock::lockExclusive()
{
    if (!writeLevel++) { // we are the first writer + lock "new" readers out
        if (!readLevel) { // no old readers and nobody is becoming one
            writing = true;
            return true;
        }
    }
    --writeLevel;
    return false;
}

bool
Ipc::ReadWriteLock::lockHeaders()
{
    if (lockShared()) {
        if (!updating.test_and_set(std::memory_order_acquire))
            return true; // we got here first
        // the updating lock was already set by somebody else
        unlockShared();
    }
    return false;
}

void
Ipc::ReadWriteLock::unlockShared()
{
    assert(readers > 0);
    --readers;
    --readLevel;
}

void
Ipc::ReadWriteLock::unlockExclusive()
{
    assert(writing);
    appending = false;
    writing = false;
    --writeLevel;
}

void
Ipc::ReadWriteLock::unlockHeaders()
{
    AssertFlagIsSet(updating);
    updating.clear(std::memory_order_release);
    unlockShared();
}

void
Ipc::ReadWriteLock::switchExclusiveToShared()
{
    assert(writing);
    ++readLevel; // must be done before we release exclusive control
    ++readers;
    unlockExclusive();
}

void
Ipc::ReadWriteLock::startAppending()
{
    assert(writing);
    appending = true;
}

void
Ipc::ReadWriteLock::updateStats(ReadWriteLockStats &stats) const
{
    if (readers) {
        ++stats.readable;
        stats.readers += readers;
    } else if (writing) {
        ++stats.writeable;
        ++stats.writers;
        stats.appenders += appending;
    } else {
        ++stats.idle;
    }
    ++stats.count;
}

/* Ipc::ReadWriteLockStats */

Ipc::ReadWriteLockStats::ReadWriteLockStats()
{
    memset(this, 0, sizeof(*this));
}

void
Ipc::ReadWriteLockStats::dump(StoreEntry &e) const
{
    storeAppendPrintf(&e, "Available locks: %9d\n", count);

    if (!count)
        return;

    storeAppendPrintf(&e, "Reading: %9d %6.2f%%\n",
                      readable, (100.0 * readable / count));
    storeAppendPrintf(&e, "Writing: %9d %6.2f%%\n",
                      writeable, (100.0 * writeable / count));
    storeAppendPrintf(&e, "Idle:    %9d %6.2f%%\n",
                      idle, (100.0 * idle / count));

    if (readers || writers) {
        const int locked = readers + writers;
        storeAppendPrintf(&e, "Readers:         %9d %6.2f%%\n",
                          readers, (100.0 * readers / locked));
        const double appPerc = writers ? (100.0 * appenders / writers) : 0.0;
        storeAppendPrintf(&e, "Writers:         %9d %6.2f%% including Appenders: %9d %6.2f%%\n",
                          writers, (100.0 * writers / locked),
                          appenders, appPerc);
    }
}

