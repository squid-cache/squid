/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_DISKS_H
#define SQUID_STORE_DISKS_H

#include "ipc/forward.h"
#include "store/Controlled.h"
#include "store/forward.h"

namespace Store {

/// summary view of all disk caches (cache_dirs) combined
class Disks: public Controlled
{
public:
    Disks();

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
    virtual void reference(StoreEntry &) override;
    virtual bool dereference(StoreEntry &e) override;
    virtual void updateHeaders(StoreEntry *) override;
    virtual void maintain() override;
    virtual bool anchorToCache(StoreEntry &e, bool &inSync) override;
    virtual bool updateAnchored(StoreEntry &) override;
    virtual void evictCached(StoreEntry &) override;
    virtual void evictIfFound(const cache_key *) override;
    virtual int callback() override;

    /// update configuration, including limits (re)calculation
    void configure();
    /// parses a single cache_dir configuration line
    static void Parse(DiskConfig &);
    /// prints the configuration into the provided StoreEntry
    static void Dump(const DiskConfig &, StoreEntry &, const char *name);

    /// Additional unknown-size entry bytes required by disks in order to
    /// reduce the risk of selecting the wrong disk cache for the growing entry.
    int64_t accumulateMore(const StoreEntry&) const;
    /// whether any disk cache is SMP-aware
    static bool SmpAware();
    static SwapDir *SelectSwapDir(const StoreEntry *);
    /// whether any of disk caches has entry with e.key
    bool hasReadableEntry(const StoreEntry &) const;
    /// \returns true if each of active cache_dirs is indexed or there are no active dirs at all
    static bool AllIndexed();
    /// handles the Coordinator notification about a ready disker
    static void DiskerReadyNotification(int kidId, bool indexed);

private:
    /* migration logic */
    SwapDir *store(int const x) const;
    static SwapDir &Dir(int const idx);

    int64_t largestMinimumObjectSize; ///< maximum of all Disk::minObjectSize()s
    int64_t largestMaximumObjectSize; ///< maximum of all Disk::maxObjectSize()s
    int64_t secondLargestMaximumObjectSize; ///< the second-biggest Disk::maxObjectSize()
};

} // namespace Store

/* Store::Disks globals that should be converted to use RegisteredRunner */
void storeDirOpenSwapLogs(void);
int storeDirWriteCleanLogs(int reopen);
void storeDirCloseSwapLogs(void);

/* Globals that should be converted to static Store::Disks methods */
void allocate_new_swapdir(Store::DiskConfig &swap);
void free_cachedir(Store::DiskConfig *swap);

/* Globals that should be moved to some Store::UFS-specific logging module */
void storeDirSwapLog(const StoreEntry *e, int op);

#endif /* SQUID_STORE_DISKS_H */

