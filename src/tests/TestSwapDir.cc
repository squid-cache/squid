#include "config.h"

#include "squid.h"
#include "TestSwapDir.h"

size_t
TestSwapDir::maxSize() const
{
    return 3;
}

void
TestSwapDir::stat(StoreEntry &) const
{
    const_cast<TestSwapDir *>(this)->statsCalled = true;
}

void
TestSwapDir::reconfigure(int, char*)
{}

void
TestSwapDir::init()
{}

int
TestSwapDir::canStore(const StoreEntry&) const
{
    return true;
}

RefCount<storeIOState>
TestSwapDir::createStoreIO(StoreEntry&, void (*)(void*, int, storeIOState*), void (*)(void*, int, storeIOState*), void*)
{
    return NULL;
}

RefCount<storeIOState>
TestSwapDir::openStoreIO(StoreEntry&, void (*)(void*, int, storeIOState*), void (*)(void*, int, storeIOState*), void*)
{
    return NULL;
}

void
TestSwapDir::parse(int, char*)
{}

StoreSearch *
TestSwapDir::search(String, HttpRequest *)
{
    return NULL;
}
