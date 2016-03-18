/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
    /// somebody needs this entry (many cache replacement policies need to know)
    virtual void reference(StoreEntry &e) = 0;

    /// somebody no longer needs this entry (usually after calling reference())
    /// return false iff the idle entry should be destroyed
    virtual bool dereference(StoreEntry &e) = 0;

    /// make stored metadata and HTTP headers the same as in the given entry
    virtual void updateHeaders(StoreEntry *) {}

    /// If this storage cannot cache collapsed entries, return false.
    /// If the entry is not found, return false. Otherwise, return true after
    /// tying the entry to this cache and setting inSync to updateCollapsed().
    virtual bool anchorCollapsed(StoreEntry &, bool &/*inSync*/) { return false; }

    /// Update a local collapsed entry with fresh info from this cache (if any).
    /// Return true iff the cache supports collapsed entries and
    /// the given local collapsed entry is now in sync with this storage.
    virtual bool updateCollapsed(StoreEntry &) { return false; }
};

} // namespace Store

#endif /* SQUID_STORE_CONTROLLED_H */

