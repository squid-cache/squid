/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
#include "store/Controlled.h"

// StoreEntry restoration info not already stored by Ipc::StoreMap
struct MemStoreMapExtraItem {
    Ipc::Mem::PageId page; ///< shared memory page with entry slice content
};
typedef Ipc::StoreMapItems<MemStoreMapExtraItem> MemStoreMapExtras;
typedef Ipc::StoreMap MemStoreMap;

class ShmWriter;

/// Stores HTTP entities in RAM. Current implementation uses shared memory.
/// Unlike a disk store (SwapDir), operations are synchronous (and fast).
class MemStore: public Store::Controlled, public Ipc::StoreMapCleaner
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

    /// called when the entry is about to forget its association with mem cache
    void disconnect(StoreEntry &e);

    /* Storage API */
    virtual void create() override {}
    virtual void init() override;
    virtual StoreEntry *get(const cache_key *) override;
    virtual uint64_t maxSize() const override;
    virtual uint64_t minSize() const override;
    virtual uint64_t currentSize() const override;
    virtual uint64_t currentCount() const override;
    virtual int64_t maxObjectSize() const override;
    virtual void getStats(StoreInfoStats &stats) const override;
    virtual void stat(StoreEntry &e) const override;
    virtual void reference(StoreEntry &e) override;
    virtual bool dereference(StoreEntry &e) override;
    virtual void updateHeaders(StoreEntry *e) override;
    virtual void maintain() override;
    virtual bool anchorToCache(StoreEntry &e, bool &inSync) override;
    virtual bool updateAnchored(StoreEntry &) override;
    virtual void evictCached(StoreEntry &) override;
    virtual void evictIfFound(const cache_key *) override;

    /// whether Squid is correctly configured to use a shared memory cache
    static bool Enabled() { return EntryLimit() > 0; }
    static int64_t EntryLimit();
    /// whether Squid is configured to use a shared memory cache
    /// (it may still be disabled due to the implicit minimum entry size limit)
    static bool Requested();

protected:
    friend ShmWriter;

    bool shouldCache(StoreEntry &e) const;
    bool startCaching(StoreEntry &e);

    void copyToShm(StoreEntry &e);
    void copyToShmSlice(StoreEntry &e, Ipc::StoreMapAnchor &anchor, Ipc::StoreMap::Slice &slice);
    bool copyFromShm(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor);
    bool copyFromShmSlice(StoreEntry &e, const StoreIOBuffer &buf, bool eof);

    void updateHeadersOrThrow(Ipc::StoreMapUpdate &update);

    void anchorEntry(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor);
    bool updateAnchoredWith(StoreEntry &, const sfileno, const Ipc::StoreMapAnchor &);

    Ipc::Mem::PageId pageForSlice(Ipc::StoreMapSliceId sliceId);
    Ipc::StoreMap::Slice &nextAppendableSlice(const sfileno entryIndex, sfileno &sliceOffset);
    sfileno reserveSapForWriting(Ipc::Mem::PageId &page);

    // Ipc::StoreMapCleaner API
    virtual void noteFreeMapSlice(const Ipc::StoreMapSliceId sliceId) override;

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

