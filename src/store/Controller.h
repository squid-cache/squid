/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
    virtual StoreEntry *get(const cache_key *) override;
    virtual uint64_t maxSize() const override;
    virtual uint64_t minSize() const override;
    virtual uint64_t currentSize() const override;
    virtual uint64_t currentCount() const override;
    virtual int64_t maxObjectSize() const override;
    virtual void getStats(StoreInfoStats &stats) const override;
    virtual void stat(StoreEntry &) const override;
    virtual void sync() override;
    virtual void maintain() override;
    virtual void markForUnlink(StoreEntry &) override;
    virtual void unlink(StoreEntry &) override;
    virtual int callback() override;
    virtual bool smpAware() const override;

    /// Additional unknown-size entry bytes required by Store in order to
    /// reduce the risk of selecting the wrong disk cache for the growing entry.
    int64_t accumulateMore(StoreEntry &) const;

    /// slowly calculate (and cache) hi/lo watermarks and similar limits
    void updateLimits();

    /// called when the entry is no longer needed by any transaction
    void handleIdleEntry(StoreEntry &);

    /// called to get rid of no longer needed entry data in RAM, if any
    void memoryOut(StoreEntry &, const bool preserveSwappable);

    /// update old entry metadata and HTTP headers using a newer entry
    void updateOnNotModified(StoreEntry *old, const StoreEntry &newer);

    /// makes the entry available for collapsing future requests
    void allowCollapsing(StoreEntry *, const RequestFlags &, const HttpRequestMethod &);

    /// marks the entry completed for collapsed requests
    void transientsCompleteWriting(StoreEntry &);

    /// Update local intransit entry after changes made by appending worker.
    void syncCollapsed(const sfileno);

    /// calls Root().transients->abandon() if transients are tracked
    void transientsAbandon(StoreEntry &);

    /// number of the transient entry readers some time ago
    int transientReaders(const StoreEntry &) const;

    /// disassociates the entry from the intransit table
    void transientsDisconnect(MemObject &);

    /// removes the entry from the memory cache
    void memoryUnlink(StoreEntry &);

    /// disassociates the entry from the memory cache, preserving cached data
    void memoryDisconnect(StoreEntry &);

    /// \returns an iterator for all Store entries
    StoreSearch *search();

    /// the number of cache_dirs being rebuilt; TODO: move to Disks::Rebuilding
    static int store_dirs_rebuilding;

private:
    /// update reference counters of the recently touched entry
    void referenceBusy(StoreEntry &e);
    /// dereference() an idle entry and return true if the entry should be deleted
    bool dereferenceIdle(StoreEntry &, bool wantsLocalMemory);

    StoreEntry *find(const cache_key *key);
    bool keepForLocalMemoryCache(StoreEntry &e) const;
    bool anchorCollapsed(StoreEntry &, bool &inSync);

    Disks *swapDir; ///< summary view of all disk caches
    Memory *memStore; ///< memory cache

    /// A shared table of public store entries that do not know whether they
    /// will belong to a memory cache, a disk cache, or will be uncachable
    /// when the response header comes. Used for SMP collapsed forwarding.
    Transients *transients;
};

/// safely access controller singleton
extern Controller &Root();

/// initialize the storage module; a custom root is used by unit tests only
extern void Init(Controller *root = nullptr);

/// undo Init()
extern void FreeMemory();

} // namespace Store

#endif /* SQUID_STORE_CONTROLLER_H */

