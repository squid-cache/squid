/*
 * DEBUG: section 54    Interprocess Communication
 */

#include "squid.h"
#include "Store.h"
#include "ipc/ReadWriteLock.h"

bool
Ipc::ReadWriteLock::lockShared()
{
    ++readers; // this locks "new" writers out
    if (!writers) // there are no old writers
        return true;
    --readers;
    return false;
}

bool
Ipc::ReadWriteLock::lockExclusive()
{
    if (!writers++) { // we are the first writer + this locks "new" readers out
        if (!readers) // there are no old readers
            return true;
    }
    --writers;
    return false;
}

void
Ipc::ReadWriteLock::unlockShared()
{
    assert(readers-- > 0);
}

void
Ipc::ReadWriteLock::unlockExclusive()
{
    assert(writers-- > 0);
}

void
Ipc::ReadWriteLock::switchExclusiveToShared()
{
    ++readers; // must be done before we release exclusive control
    unlockExclusive();
}

void
Ipc::ReadWriteLock::updateStats(ReadWriteLockStats &stats) const
{
    if (readers) {
        ++stats.readable;
        stats.readers += readers;
    } else if (writers) {
        ++stats.writeable;
        stats.writers += writers;
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
        storeAppendPrintf(&e, "Writers:         %9d %6.2f%%\n",
                          writers, (100.0 * writers / locked));
    }
}
