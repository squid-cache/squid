/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"
#include "testStore.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testStore );

int
TestStore::callback()
{
    return 1;
}

StoreEntry*
TestStore::get(const cache_key*)
{
    return NULL;
}

void
TestStore::get(String, void (*)(StoreEntry*, void*), void*)
{}

void
TestStore::init()
{}

uint64_t
TestStore::maxSize() const
{
    return 3;
}

uint64_t
TestStore::minSize() const
{
    return 1;
}

uint64_t
TestStore::currentSize() const
{
    return 2;
}

uint64_t
TestStore::currentCount() const
{
    return 2;
}

int64_t
TestStore::maxObjectSize() const
{
    return 1;
}

void
TestStore::getStats(StoreInfoStats &) const
{
}

void
TestStore::stat(StoreEntry &) const
{
    const_cast<TestStore *>(this)->statsCalled = true;
}

StoreSearch *
TestStore::search()
{
    return NULL;
}

void
testStore::testSetRoot()
{
    Store::Controller *aStore(new TestStore);
    Store::Init(aStore);

    CPPUNIT_ASSERT_EQUAL(&Store::Root(), aStore);
    Store::FreeMemory();
}

void
testStore::testUnsetRoot()
{
    Store::Controller *aStore(new TestStore);
    Store::Controller *aStore2(new TestStore);
    Store::Init(aStore);
    Store::FreeMemory();
    Store::Init(aStore2);
    CPPUNIT_ASSERT_EQUAL(&Store::Root(),aStore2);
    Store::FreeMemory();
}

void
testStore::testStats()
{
    TestStore *aStore(new TestStore);
    Store::Init(aStore);
    CPPUNIT_ASSERT_EQUAL(false, aStore->statsCalled);
    Store::Stats(NullStoreEntry::getInstance());
    CPPUNIT_ASSERT_EQUAL(true, aStore->statsCalled);
    Store::FreeMemory();
}

void
testStore::testMaxSize()
{
    Store::Controller *aStore(new TestStore);
    Store::Init(aStore);
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(3), aStore->maxSize());
    Store::FreeMemory();
}

