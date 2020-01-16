/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_DISKS_H
#define SQUID_STORE_DISKS_H

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

    /// slowly calculate (and cache) hi/lo watermarks and similar limits
    void updateLimits();

    /// Additional unknown-size entry bytes required by disks in order to
    /// reduce the risk of selecting the wrong disk cache for the growing entry.
    int64_t accumulateMore(const StoreEntry&) const;
    virtual bool smpAware() const override;
    /// whether any of disk caches has entry with e.key
    bool hasReadableEntry(const StoreEntry &) const;

private:
    /* migration logic */
    SwapDir *store(int const x) const;
    SwapDir &dir(int const idx) const;

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
void allocate_new_swapdir(Store::DiskConfig *swap);
void free_cachedir(Store::DiskConfig *swap);

/* Globals that should be converted to Store::Disks private data members */
typedef int STDIRSELECT(const StoreEntry *e);
extern STDIRSELECT *storeDirSelectSwapDir;

/* Globals that should be moved to some Store::UFS-specific logging module */
void storeDirSwapLog(const StoreEntry *e, int op);

#endif /* SQUID_STORE_DISKS_H */

