#include "config.h"

#include "squid.h"
#include "TestSwapDir.h"

uint64_t
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

StoreIOState::Pointer
TestSwapDir::createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *)
{
    return NULL;
}

StoreIOState::Pointer
TestSwapDir::openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *)
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
