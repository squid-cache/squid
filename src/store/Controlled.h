/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_CONTROLLED_H
#define SQUID_STORE_CONTROLLED_H

#include "store/Storage.h"

namespace Store {

/// Storage controlled by a Controller.
/// This API is shared among Disks, Disk, Memory caches and Transients.
class Controlled: public Storage
{
public:
    /// \returns a possibly unlocked/unregistered stored entry with key (or nil)
    /// The returned entry might not match the caller's Store ID or method. The
    /// caller must abandon()/release() the entry or register it with Root().
    /// This method must not trigger slow I/O operations (e.g., disk swap in).
    virtual StoreEntry *get(const cache_key *) = 0;

    /// somebody needs this entry (many cache replacement policies need to know)
    virtual void reference(StoreEntry &e) = 0;

    /// somebody no longer needs this entry (usually after calling reference())
    /// return false iff the idle entry should be destroyed
    virtual bool dereference(StoreEntry &e) = 0;

    /// make stored metadata and HTTP headers the same as in the given entry
    virtual void updateHeaders(StoreEntry *) {}

    /// If Transients entry cannot be attached to this storage, return false.
    /// If the entry is not found, return false. Otherwise, return true after
    /// tying the entry to this cache and setting inSync to updateAnchored().
    virtual bool anchorToCache(StoreEntry &, bool &/*inSync*/) { return false; }

    /// Update a local Transients entry with fresh info from this cache (if any).
    /// Return true iff the cache supports Transients entries and
    /// the given local Transients entry is now in sync with this storage.
    virtual bool updateAnchored(StoreEntry &) { return false; }
};

} // namespace Store

#endif /* SQUID_STORE_CONTROLLED_H */

