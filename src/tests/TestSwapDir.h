#ifndef TEST_TESTSWAPDIR
#define TEST_TESTSWAPDIR

#include "squid.h"
#include "SwapDir.h"

class TestSwapDir : public SwapDir
{

public:
    TestSwapDir() : SwapDir("test"), statsCalled (false) {}

    bool statsCalled;

    virtual uint64_t maxSize() const;
    virtual void stat(StoreEntry &) const; /* output stats to the provided store entry */

    virtual void reconfigure(int, char*);
    virtual void init();
    virtual int canStore(const StoreEntry&) const;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void parse(int, char*);
    virtual StoreSearch *search(String, HttpRequest *);
};

typedef RefCount<TestSwapDir> TestSwapDirPointer;

#endif  /* TEST_TESTSWAPDIR */
