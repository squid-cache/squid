/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TRANSIENTS_H
#define SQUID_TRANSIENTS_H

#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "Store.h"
#include "store/Controlled.h"
#include "store/forward.h"
#include <vector>

typedef Ipc::StoreMap TransientsMap;

/// Keeps track of store entries being delivered to clients that arrived before
/// those entries were [fully] cached. This SMP-shared table is necessary to
/// * sync an entry-writing worker with entry-reading worker(s); and
/// * sync an entry-deleting worker with both entry-reading/writing workers.
class Transients: public Store::Controlled, public Ipc::StoreMapCleaner
{
public:
    /// shared entry metadata, used for synchronization
    class EntryStatus
    {
    public:
        bool abortedByWriter = false; ///< whether the entry was aborted
        bool waitingToBeFreed = false; ///< whether the entry was marked for deletion
        bool collapsed = false; ///< whether the entry allows collapsing
    };

    Transients();
    virtual ~Transients();

    /// return a local, previously collapsed entry
    StoreEntry *findCollapsed(const sfileno xitIndex);

    /// removes collapsing requirement (for future hits)
    void clearCollapsingRequirement(const StoreEntry &e);

    /// start listening for remote DELETE requests targeting either a complete
    /// StoreEntry (ioReading) or a being-formed miss StoreEntry (ioWriting)
    void monitorIo(StoreEntry*, const cache_key*, const Store::IoStatus);

    /// called when the in-transit entry has been successfully cached
    void completeWriting(const StoreEntry &e);

    /// copies current shared entry metadata into entryStatus
    void status(const StoreEntry &e, EntryStatus &entryStatus) const;

    /// number of entry readers some time ago
    int readers(const StoreEntry &e) const;

    /// the caller is done writing or reading the given entry
    void disconnect(StoreEntry &);

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
    virtual void evictCached(StoreEntry &) override;
    virtual void evictIfFound(const cache_key *) override;
    virtual void maintain() override;

    /// Whether an entry with the given public key exists and (but) was
    /// marked for removal some time ago; get(key) returns nil in such cases.
    bool markedForDeletion(const cache_key *) const;

    /// whether the entry is in "reading from Transients" I/O state
    bool isReader(const StoreEntry &) const;
    /// whether the entry is in "writing to Transients" I/O state
    bool isWriter(const StoreEntry &) const;
    /// whether we or somebody else is in the "writing to Transients" I/O state
    bool hasWriter(const StoreEntry &);

    static int64_t EntryLimit();

    /// Can we create and initialize Transients?
    static bool Enabled() { return EntryLimit(); }

protected:
    void addEntry(StoreEntry*, const cache_key *, const Store::IoStatus);
    void addWriterEntry(StoreEntry &, const cache_key *);
    void addReaderEntry(StoreEntry &, const cache_key *);
    void anchorEntry(StoreEntry &, const sfileno, const Ipc::StoreMapAnchor &);

    // Ipc::StoreMapCleaner API
    virtual void noteFreeMapSlice(const Ipc::StoreMapSliceId sliceId) override;

private:
    /// shared packed info indexed by Store keys, for creating new StoreEntries
    TransientsMap *map;

    typedef std::vector<StoreEntry*> Locals;
    /// local collapsed reader and writer entries, indexed by transient ID,
    /// for syncing old StoreEntries
    Locals *locals;
};

// TODO: Why use Store as a base? We are not really a cache.

#endif /* SQUID_TRANSIENTS_H */

