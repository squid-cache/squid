/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "TestSwapDir.h"

uint64_t
TestSwapDir::maxSize() const
{
    return 3;
}

uint64_t
TestSwapDir::currentSize() const
{
    return 2;
}

uint64_t
TestSwapDir::currentCount() const
{
    return 2;
}

void
TestSwapDir::stat(StoreEntry &) const
{
    const_cast<TestSwapDir *>(this)->statsCalled = true;
}

void
TestSwapDir::reconfigure()
{}

void
TestSwapDir::init()
{}

bool
TestSwapDir::unlinkdUseful() const
{
    return false;
}

bool
TestSwapDir::canStore(const StoreEntry &, int64_t, int &load) const
{
    load = 0;
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

