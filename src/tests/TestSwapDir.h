#ifndef TEST_TESTSWAPDIR
#define TEST_TESTSWAPDIR

#include "squid.h"
#include "SwapDir.h"

class TestSwapDir : public SwapDir
{

public:
    TestSwapDir() : SwapDir("test"), statsCalled (false) {}

    bool statsCalled;

    virtual size_t maxSize() const;
    virtual void stat(StoreEntry &) const; /* output stats to the provided store entry */

    virtual void reconfigure(int, char*);
    virtual void init();
    virtual int canStore(const StoreEntry&) const;
    virtual RefCount<storeIOState> createStoreIO(StoreEntry&, void
            (*)(void*, int, storeIOState*), void (*)(void*, int, storeIOState*), void*);
    virtual RefCount<storeIOState> openStoreIO(StoreEntry&, void
            (*)(void*, int, storeIOState*), void (*)(void*, int, storeIOState*), void*);
    virtual void parse(int, char*);
    virtual StoreSearch *search(String, HttpRequest *);
};

typedef RefCount<TestSwapDir> TestSwapDirPointer;

#endif  /* TEST_TESTSWAPDIR */
