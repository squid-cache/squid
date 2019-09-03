/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_CONTROLLER_H
#define SQUID_STORE_CONTROLLER_H

#include "store/Storage.h"

class MemObject;
class RequestFlags;
class HttpRequestMethod;

namespace Store {

/// Public Store interface. Coordinates the work of memory/disk/transient stores
/// and hides their individual existence/differences from the callers.
class Controller: public Storage
{
public:
    Controller();
    virtual ~Controller() override;

    /* Storage API */
    virtual void create() override;
    virtual void init() override;
    virtual uint64_t maxSize() const override;
    virtual uint64_t minSize() const override;
    virtual uint64_t currentSize() const override;
    virtual uint64_t currentCount() const override;
    virtual int64_t maxObjectSize() const override;
    virtual void getStats(StoreInfoStats &stats) const override;
    virtual void stat(StoreEntry &) const override;
    virtual void sync() override;
    virtual void maintain() override;
    virtual void evictCached(StoreEntry &) override;
    virtual void evictIfFound(const cache_key *) override;
    virtual int callback() override;

    /// \returns a locally indexed and SMP-tracked matching StoreEntry (or nil)
    /// Slower than peek() but does not restrict StoreEntry use and storage.
    /// Counts as an entry reference from the removal policy p.o.v.
    StoreEntry *find(const cache_key *);

    /// \returns a matching StoreEntry not suitable for long-term use (or nil)
    /// Faster than find() but the returned entry may not receive updates, may
    /// lack information from some of the Stores, and should not be updated
    /// except that purging peek()ed entries is supported.
    /// Does not count as an entry reference from the removal policy p.o.v.
    StoreEntry *peek(const cache_key *);

    /// \returns matching StoreEntry associated with local ICP/HTCP transaction
    /// Warning: The returned StoreEntry is not synced and may be marked for
    /// deletion. It can only be used for extracting transaction callback details.
    /// New code should be designed to avoid this deprecated API.
    StoreEntry *findCallbackXXX(const cache_key *);

    /// Whether a transient entry with the given public key exists and (but) was
    /// marked for removal some time ago; get(key) returns nil in such cases.
    bool markedForDeletion(const cache_key *key) const;

    /// markedForDeletion() with no readers
    /// this is one method because the two conditions must be checked in the right order
    bool markedForDeletionAndAbandoned(const StoreEntry &) const;

    /// whether there is a disk entry with e.key
    bool hasReadableDiskEntry(const StoreEntry &) const;

    /// Additional unknown-size entry bytes required by Store in order to
    /// reduce the risk of selecting the wrong disk cache for the growing entry.
    int64_t accumulateMore(StoreEntry &) const;

    /// slowly calculate (and cache) hi/lo watermarks and similar limits
    void updateLimits();

    /// called when the entry is no longer needed by any transaction
    void handleIdleEntry(StoreEntry &);

    /// Evict memory cache entries to free at least `spaceRequired` bytes.
    /// Should be called via storeGetMemSpace().
    /// Unreliable: Fails if enough victims cannot be found fast enough.
    void freeMemorySpace(const int spaceRequired);

    /// called to get rid of no longer needed entry data in RAM, if any
    void memoryOut(StoreEntry &, const bool preserveSwappable);

    /// using a 304 response, update the old entry (metadata and reply headers)
    void updateOnNotModified(StoreEntry *old, StoreEntry &e304);

    /// tries to make the entry available for collapsing future requests
    bool allowCollapsing(StoreEntry *, const RequestFlags &, const HttpRequestMethod &);

    /// register a being-read StoreEntry (to optimize concurrent cache reads
    /// and to receive remote DELETE events)
    void addReading(StoreEntry *, const cache_key *);

    /// register a being-written StoreEntry (to support concurrent cache reads
    /// and to receive remote DELETE events)
    void addWriting(StoreEntry *, const cache_key *);

    /// whether the entry is in "reading from Transients" I/O state
    bool transientsReader(const StoreEntry &) const;

    /// whether the entry is in "writing to Transients" I/O state
    bool transientsWriter(const StoreEntry &) const;

    /// marks the entry completed for collapsed requests
    void transientsCompleteWriting(StoreEntry &);

    /// Update local intransit entry after changes made by appending worker.
    void syncCollapsed(const sfileno);

    /// stop any current (and prevent any future) SMP sharing of the given entry
    void stopSharing(StoreEntry &);

    /// number of the transient entry readers some time ago
    int transientReaders(const StoreEntry &) const;

    /// disassociates the entry from the intransit table
    void transientsDisconnect(StoreEntry &);

    /// removes collapsing requirement (for future hits)
    void transientsClearCollapsingRequirement(StoreEntry &e);

    /// disassociates the entry from the memory cache, preserving cached data
    void memoryDisconnect(StoreEntry &);

    /// \returns an iterator for all Store entries
    StoreSearch *search();

    /// whether there are any SMP-aware storages
    static bool SmpAware();

    /// the number of cache_dirs being rebuilt; TODO: move to Disks::Rebuilding
    static int store_dirs_rebuilding;

private:
    bool memoryCacheHasSpaceFor(const int pagesRequired) const;

    void referenceBusy(StoreEntry &e);
    bool dereferenceIdle(StoreEntry &, bool wantsLocalMemory);

    void allowSharing(StoreEntry &, const cache_key *);
    StoreEntry *peekAtLocal(const cache_key *);

    void memoryEvictCached(StoreEntry &);
    void transientsUnlinkByKeyIfFound(const cache_key *);
    bool keepForLocalMemoryCache(StoreEntry &e) const;
    bool anchorToCache(StoreEntry &e, bool &inSync);
    void checkTransients(const StoreEntry &) const;

    Disks *swapDir; ///< summary view of all disk caches
    Memory *sharedMemStore; ///< memory cache that multiple workers can use
    bool localMemStore; ///< whether local (non-shared) memory cache is enabled

    /// A shared table of public store entries that do not know whether they
    /// will belong to a memory cache, a disk cache, or will be uncachable
    /// when the response header comes. Used for SMP collapsed forwarding.
    Transients *transients;

    /// Hack: Relays page shortage from freeMemorySpace() to handleIdleEntry().
    int memoryPagesDebt_ = 0;
};

/// safely access controller singleton
extern Controller &Root();

/// initialize the storage module; a custom root is used by unit tests only
extern void Init(Controller *root = nullptr);

/// undo Init()
extern void FreeMemory();

} // namespace Store

#endif /* SQUID_STORE_CONTROLLER_H */

