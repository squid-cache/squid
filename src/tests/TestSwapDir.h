/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef TEST_TESTSWAPDIR
#define TEST_TESTSWAPDIR

#include "SwapDir.h"

class TestSwapDir : public SwapDir
{

public:
    TestSwapDir() : SwapDir("test"), statsCalled (false) {}

    bool statsCalled;

    virtual uint64_t maxSize() const;
    virtual uint64_t currentSize() const;
    virtual uint64_t currentCount() const;
    virtual void stat(StoreEntry &) const; /* output stats to the provided store entry */
    virtual void swappedOut(const StoreEntry &e) {}

    virtual void reconfigure();
    virtual void init();
    virtual bool unlinkdUseful() const;
    virtual bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void parse(int, char*);
    virtual StoreSearch *search(String, HttpRequest *);
};

typedef RefCount<TestSwapDir> TestSwapDirPointer;

#endif  /* TEST_TESTSWAPDIR */

