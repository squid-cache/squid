/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef TEST_TESTSWAPDIR
#define TEST_TESTSWAPDIR

#include "store/Disk.h"

class TestSwapDir : public SwapDir
{

public:
    TestSwapDir() : SwapDir("test"), statsCalled (false) {}

    bool statsCalled;

    /* Store::Disk API */
    virtual uint64_t maxSize() const override;
    virtual uint64_t currentSize() const override;
    virtual uint64_t currentCount() const override;
    virtual void stat(StoreEntry &) const override;
    virtual void finalizeSwapoutSuccess(const StoreEntry &) override {}
    virtual void finalizeSwapoutFailure(StoreEntry &) override {}
    virtual void reconfigure() override;
    virtual void init() override;
    virtual bool unlinkdUseful() const override;
    virtual bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const override;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) override;
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) override;
    virtual void parse(int, char*) override;
    virtual void evictCached(StoreEntry &) override {}
    virtual void evictIfFound(const cache_key *) override {}
    virtual bool hasReadableEntry(const StoreEntry &) const override { return false; }
};

typedef RefCount<TestSwapDir> TestSwapDirPointer;

#endif  /* TEST_TESTSWAPDIR */

