/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TRANSIENTS_H
#define SQUID_TRANSIENTS_H

#include "http/MethodType.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "Store.h"
#include "store/Controlled.h"
#include <vector>

// StoreEntry restoration info not already stored by Ipc::StoreMap
struct TransientsMapExtraItem {
    char url[MAX_URL+1]; ///< Request-URI; TODO: decrease MAX_URL by one
    RequestFlags reqFlags; ///< request flags
    Http::MethodType reqMethod; ///< request method; extensions are not supported
};
typedef Ipc::StoreMapItems<TransientsMapExtraItem> TransientsMapExtras;
typedef Ipc::StoreMap TransientsMap;

/// Keeps track of store entries being delivered to clients that arrived before
/// those entries were [fully] cached. This shared table is necessary to sync
/// the entry-writing worker with entry-reading worker(s).
class Transients: public Store::Controlled, public Ipc::StoreMapCleaner
{
public:
    Transients();
    virtual ~Transients();

    /// return a local, previously collapsed entry
    StoreEntry *findCollapsed(const sfileno xitIndex);

    /// add an in-transit entry suitable for collapsing future requests
    void startWriting(StoreEntry *e, const RequestFlags &reqFlags, const HttpRequestMethod &reqMethod);

    /// called when the in-transit entry has been successfully cached
    void completeWriting(const StoreEntry &e);

    /// the calling entry writer no longer expects to cache this entry
    void abandon(const StoreEntry &e);

    /// whether an in-transit entry is now abandoned by its writer
    bool abandoned(const StoreEntry &e) const;

    /// number of entry readers some time ago
    int readers(const StoreEntry &e) const;

    /// the caller is done writing or reading this entry
    void disconnect(MemObject &mem_obj);

    /* Store API */
    virtual StoreEntry *get(const cache_key *) override;
    virtual void create() override {}
    virtual void init() override;
    virtual uint64_t maxSize() const override;
    virtual uint64_t minSize() const override;
    virtual uint64_t currentSize() const override;
    virtual uint64_t currentCount() const override;
    virtual int64_t maxObjectSize() const override;
    virtual void getStats(StoreInfoStats &stats) const override;
    virtual void stat(StoreEntry &e) const override;
    virtual void reference(StoreEntry &e) override;
    virtual bool dereference(StoreEntry &e) override;
    virtual void markForUnlink(StoreEntry &e) override;
    virtual void unlink(StoreEntry &e) override;
    virtual void maintain() override;
    virtual bool smpAware() const override { return true; }

    static int64_t EntryLimit();

protected:
    StoreEntry *copyFromShm(const sfileno index);
    bool copyToShm(const StoreEntry &e, const sfileno index, const RequestFlags &reqFlags, const HttpRequestMethod &reqMethod);

    bool abandonedAt(const sfileno index) const;

    // Ipc::StoreMapCleaner API
    virtual void noteFreeMapSlice(const Ipc::StoreMapSliceId sliceId) override;

private:
    /// shared packed info indexed by Store keys, for creating new StoreEntries
    TransientsMap *map;

    /// shared packed info that standard StoreMap does not store for us
    typedef TransientsMapExtras Extras;
    Ipc::Mem::Pointer<Extras> extras;

    typedef std::vector<StoreEntry*> Locals;
    /// local collapsed entries indexed by transient ID, for syncing old StoreEntries
    Locals *locals;
};

// TODO: Why use Store as a base? We are not really a cache.

#endif /* SQUID_TRANSIENTS_H */

