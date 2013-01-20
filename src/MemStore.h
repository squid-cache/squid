#ifndef SQUID_MEMSTORE_H
#define SQUID_MEMSTORE_H

#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "Store.h"

// StoreEntry restoration info not already stored by Ipc::StoreMap
struct MemStoreMapExtras {
    Ipc::Mem::PageId page; ///< shared memory page with entry slice content
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
    void keep(StoreEntry &e);

    bool copyToShm(StoreEntry &e, const sfileno index, Ipc::StoreMapAnchor &anchor);
    bool copyToShmSlice(StoreEntry &e, const sfileno index, Ipc::StoreMapAnchor &anchor, int64_t &offset);
    bool copyFromShm(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor);
    bool copyFromShmSlice(StoreEntry &e, StoreIOBuffer &buf, bool eof);

    sfileno reserveSapForWriting(Ipc::Mem::PageId &page);

    // Ipc::StoreMapCleaner API
    virtual void noteFreeMapSlice(const sfileno sliceId);

private:
    // TODO: move freeSlots into map
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> freeSlots; ///< unused map slot IDs
    MemStoreMap *map; ///< index of mem-cached entries

    /// the last allocate slice for writing a store entry (during copyToShm)
    sfileno lastWritingSlice;

    /// temporary storage for slot and page ID pointers; for the waiting cache
    class SlotAndPage {
    public:
        SlotAndPage(): slot(NULL), page(NULL) {}
        bool operator !() const { return !slot && !page; }
        Ipc::Mem::PageId *slot; ///< local slot variable, waiting to be filled
        Ipc::Mem::PageId *page; ///< local page variable, waiting to be filled
    };
    SlotAndPage waitingFor; ///< a cache for a single "hot" free slot and page
};

// Why use Store as a base? MemStore and SwapDir are both "caches".

// Why not just use a SwapDir API? That would not help much because Store has
// to check/update memory cache separately from the disk cache. And same API
// would hurt because we can support synchronous get/put, unlike the disks.

#endif /* SQUID_MEMSTORE_H */
