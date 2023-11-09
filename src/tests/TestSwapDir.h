/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    uint64_t maxSize() const override;
    uint64_t currentSize() const override;
    uint64_t currentCount() const override;
    void stat(StoreEntry &) const override;
    void finalizeSwapoutSuccess(const StoreEntry &) override {}
    void finalizeSwapoutFailure(StoreEntry &) override {}
    void reconfigure() override;
    void init() override;
    bool unlinkdUseful() const override;
    bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const override;
    StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    void parse(int, char*) override;
    void evictCached(StoreEntry &) override {}
    void evictIfFound(const cache_key *) override {}
    bool hasReadableEntry(const StoreEntry &) const override { return false; }
    bool smpAware() const override { return false; }
};

typedef RefCount<TestSwapDir> TestSwapDirPointer;

#endif  /* TEST_TESTSWAPDIR */

