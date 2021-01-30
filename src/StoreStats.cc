/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Statistics */

#include "squid.h"
#include "StoreStats.h"
#include "tools.h"

StoreInfoStats &
StoreInfoStats::operator +=(const StoreInfoStats &stats)
{
    swap.size += stats.swap.size;
    swap.capacity += stats.swap.capacity;
    swap.count += stats.swap.count;
    swap.open_disk_fd += stats.swap.open_disk_fd;

    // Assume that either all workers use shared memory cache or none do.
    // It is possible but difficult to report correct stats for an arbitrary
    // mix, and only rather unusual deployments can benefit from mixing.

    // If workers share memory, we will get shared stats from those workers
    // and non-shared stats from other processes. Ignore order and also
    // ignore other processes stats because they are zero in most setups.
    if (stats.mem.shared) { // workers share memory
        // use the latest reported stats, they all should be about the same
        mem.shared = true;
        mem.size = stats.mem.size;
        mem.capacity = stats.mem.capacity;
        mem.count = stats.mem.count;
    } else if (!mem.shared) { // do not corrupt shared stats, if any
        // workers do not share so we must add everything up
        mem.size += stats.mem.size;
        mem.capacity += stats.mem.capacity;
        mem.count += stats.mem.count;
    }

    store_entry_count += stats.store_entry_count;
    mem_object_count += stats.mem_object_count;

    return *this;
}

/* StoreIoStats */

StoreIoStats::StoreIoStats()
{
    memset(this, 0, sizeof(*this));
}

