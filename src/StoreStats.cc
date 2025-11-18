/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
    mem.shared = mem.shared || stats.mem.shared; // TODO: Remove mem.shared as effectively unused?
    mem.size += stats.mem.size;
    mem.capacity += stats.mem.capacity;
    mem.count += stats.mem.count;

    store_entry_count += stats.store_entry_count;
    mem_object_count += stats.mem_object_count;

    return *this;
}

/* StoreIoStats */

StoreIoStats::StoreIoStats()
{
    memset(this, 0, sizeof(*this));
}

