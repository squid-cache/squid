#ifndef SQUID_MEMSTORE_H
#define SQUID_MEMSTORE_H

#include "ipc/mem/Page.h"
#include "ipc/StoreMap.h"
#include "Store.h"

// StoreEntry restoration info not already stored by Ipc::StoreMap
struct MemStoreMapExtras {
    Ipc::Mem::PageId page; ///< shared memory page with the entry content
    int64_t storedSize; ///< total size of the stored entry content
};
typedef Ipc::StoreMapWithExtras<MemStoreMapExtras> MemStoreMap;

/// Stores HTTP entities in RAM. Current implementation uses shared memory.
/// Unlike a disk store (SwapDir), operations are synchronous (and fast).
class MemStore: public Store, public Ipc::StoreMapCleaner
{
public:
    MemStore();
    virtual ~MemStore();

    /// cache the entry or forget about it until the next considerKeeping call
    void considerKeeping(StoreEntry &e);

    /// whether e should be kept in local RAM for possible future caching
    bool keepInLocalMemory(const StoreEntry &e) const;

    /* Store API */
    virtual int callback();
    virtual StoreEntry * get(const cache_key *);
    virtual void get(String const key , STOREGETCLIENT callback, void *cbdata);
    virtual void init();
    virtual uint64_t maxSize() const;
    virtual uint64_t minSize() const;
    virtual uint64_t currentSize() const;
    virtual uint64_t currentCount() const;
    virtual int64_t maxObjectSize() const;
    virtual void getStats(StoreInfoStats &stats) const;
    virtual void stat(StoreEntry &) const;
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual void reference(StoreEntry &);
    virtual bool dereference(StoreEntry &, bool);
    virtual void maintain();

    static int64_t EntryLimit();

protected:
    bool willFit(int64_t needed) const;
    void keep(StoreEntry &e);

    bool copyToShm(StoreEntry &e, MemStoreMap::Extras &extras);
    bool copyFromShm(StoreEntry &e, const MemStoreMap::Extras &extras);

    // Ipc::StoreMapCleaner API
    virtual void cleanReadable(const sfileno fileno);

private:
    MemStoreMap *map; ///< index of mem-cached entries
    uint64_t theCurrentSize; ///< currently used space in the storage area
};

// Why use Store as a base? MemStore and SwapDir are both "caches".

// Why not just use a SwapDir API? That would not help much because Store has
// to check/update memory cache separately from the disk cache. And same API
// would hurt because we can support synchronous get/put, unlike the disks.

#endif /* SQUID_MEMSTORE_H */
