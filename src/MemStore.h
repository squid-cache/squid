/*
 * $Id$
 */

#ifndef SQUID_MEMSTORE_H
#define SQUID_MEMSTORE_H

#include "Store.h"
#include "MemStoreMap.h"

/// Stores HTTP entities in RAM. Current implementation uses shared memory.
/// Unlike a disk store (SwapDir), operations are synchronous (and fast).
class MemStore: public Store, public Ipc::StoreMapCleaner {
public:
    MemStore();
    virtual ~MemStore();

    /// cache the entry or forget about it until the next considerKeeping call
    void considerKeeping(StoreEntry &e);

    /* Store API */
    virtual int callback();
    virtual StoreEntry * get(const cache_key *);
    virtual void get(String const key , STOREGETCLIENT callback, void *cbdata);
    virtual void init();
    virtual uint64_t maxSize() const;
    virtual uint64_t minSize() const;
    virtual uint64_t currentSize() const;
    virtual uint64_t currentCount() const;
    virtual void stat(StoreEntry &) const;
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual void reference(StoreEntry &);
    virtual void dereference(StoreEntry &);
    virtual void maintain();
    virtual void updateSize(int64_t size, int sign);

    /// initializes shared memory segments before they are used by workers
    static void Init();

protected:
    bool willFit(int64_t needed);
    void keep(StoreEntry &e);

    bool copyToShm(StoreEntry &e, MemStoreMap::Extras &extras);
    bool copyFromShm(StoreEntry &e, const MemStoreMap::Extras &extras);

    // Ipc::StoreMapCleaner API
    virtual void cleanReadable(const sfileno fileno);

    static int64_t EntryLimit();

private:
    MemStoreMap *map; ///< index of mem-cached entries
    uint64_t cur_size; ///< currently used space in the storage area
};

// Why use Store as a base? MemStore and SwapDir are both "caches".

// Why not just use a SwapDir API? That would not help much because Store has
// to check/update memory cache separately from the disk cache. And same API
// would hurt because we can support synchronous get/put, unlike the disks.

#endif /* SQUID_MEMSTORE_H */
