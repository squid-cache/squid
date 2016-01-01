/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEMSTORE_H
#define SQUID_MEMSTORE_H

#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "Store.h"

// StoreEntry restoration info not already stored by Ipc::StoreMap
struct MemStoreMapExtraItem {
    Ipc::Mem::PageId page; ///< shared memory page with entry slice content
};
typedef Ipc::StoreMapItems<MemStoreMapExtraItem> MemStoreMapExtras;
typedef Ipc::StoreMap MemStoreMap;

/// Stores HTTP entities in RAM. Current implementation uses shared memory.
/// Unlike a disk store (SwapDir), operations are synchronous (and fast).
class MemStore: public Store, public Ipc::StoreMapCleaner
{
public:
    MemStore();
    virtual ~MemStore();

    /// whether e should be kept in local RAM for possible future caching
    bool keepInLocalMemory(const StoreEntry &e) const;

    /// copy non-shared entry data of the being-cached entry to our cache
    void write(StoreEntry &e);

    /// all data has been received; there will be no more write() calls
    void completeWriting(StoreEntry &e);

    /// remove from the cache
    void unlink(StoreEntry &e);

    /// called when the entry is about to forget its association with mem cache
    void disconnect(StoreEntry &e);

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
    virtual void markForUnlink(StoreEntry &e);
    virtual void reference(StoreEntry &);
    virtual bool dereference(StoreEntry &, bool);
    virtual void maintain();
    virtual bool anchorCollapsed(StoreEntry &collapsed, bool &inSync);
    virtual bool updateCollapsed(StoreEntry &collapsed);

    static int64_t EntryLimit();

protected:
    bool shouldCache(StoreEntry &e) const;
    bool startCaching(StoreEntry &e);

    void copyToShm(StoreEntry &e);
    void copyToShmSlice(StoreEntry &e, Ipc::StoreMapAnchor &anchor);
    bool copyFromShm(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor);
    bool copyFromShmSlice(StoreEntry &e, const StoreIOBuffer &buf, bool eof);

    void anchorEntry(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor);
    bool updateCollapsedWith(StoreEntry &collapsed, const sfileno index, const Ipc::StoreMapAnchor &anchor);

    sfileno reserveSapForWriting(Ipc::Mem::PageId &page);

    // Ipc::StoreMapCleaner API
    virtual void noteFreeMapSlice(const Ipc::StoreMapSliceId sliceId);

private:
    // TODO: move freeSlots into map
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> freeSlots; ///< unused map slot IDs
    MemStoreMap *map; ///< index of mem-cached entries

    typedef MemStoreMapExtras Extras;
    Ipc::Mem::Pointer<Extras> extras; ///< IDs of pages with slice data

    /// the last allocate slice for writing a store entry (during copyToShm)
    sfileno lastWritingSlice;

    /// temporary storage for slot and page ID pointers; for the waiting cache
    class SlotAndPage
    {
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

