/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_STORAGE_H
#define SQUID_STORE_STORAGE_H

#include "base/RefCount.h"
#include "http/RequestMethod.h"
#include "store/forward.h"
#include "store_key_md5.h"

class StoreInfoStats;

namespace Store {

/// A "response storage" abstraction.
/// This API is shared among Controller and Controlled classes.
class Storage: public RefCountable
{
public:
    virtual ~Storage() {}

    /// create system resources needed for this store to operate in the future
    virtual void create() = 0;

    /// Start preparing the store for use. To check readiness, callers should
    /// use readable() and writable() methods.
    virtual void init() = 0;

    /**
     * The maximum size the store will support in normal use. Inaccuracy is
     * permitted, but may throw estimates for memory etc out of whack.
     */
    virtual uint64_t maxSize() const = 0;

    /// the minimum size the store will shrink to via normal housekeeping
    virtual uint64_t minSize() const = 0;

    /// current size
    virtual uint64_t currentSize() const = 0;

    /// the total number of objects stored right now
    virtual uint64_t currentCount() const = 0;

    /// the maximum size of a storable object; -1 if unlimited
    virtual int64_t maxObjectSize() const = 0;

    /// collect statistics
    virtual void getStats(StoreInfoStats &stats) const = 0;

    /**
     * Output stats to the provided store entry.
     \todo make these calls asynchronous
     */
    virtual void stat(StoreEntry &e) const = 0;

    /// Prevent new get() calls from returning the matching entry.
    /// If the matching entry is unused, it may be removed from the store now.
    /// The store entry is matched using either `e` attachment info or `e.key`.
    virtual void evictCached(StoreEntry &e) = 0;

    /// An evictCached() equivalent for callers that did not get() a StoreEntry.
    /// Callers with StoreEntry objects must use evictCached() instead.
    virtual void evictIfFound(const cache_key *) = 0;

    /// called once every main loop iteration; TODO: Move to UFS code.
    virtual int callback() { return 0; }

    /// perform regular periodic maintenance; TODO: move to UFSSwapDir::Maintain
    virtual void maintain() = 0;

    /// prepare for shutdown
    virtual void sync() {}
};

} // namespace Store

#endif /* SQUID_STORE_STORAGE_H */

