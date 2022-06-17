/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"
#include "store/SwapMeta.h"
#include "testStore.h"
#include "unitTestMain.h"

#include <limits>

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
    StoreEntry entry;
    Store::Stats(&entry);
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

namespace Store {

static void
checkTooSmallSwapMetaRawType(const RawSwapMetaType rawType)
{
    // RawSwapMetaTypeBottom and smaller values are unrelated to any named
    // SwapMetaDataType values, including past, current, and future ones
    CPPUNIT_ASSERT(!HonoredSwapMetaType(rawType)); // current
    CPPUNIT_ASSERT(!IgnoredSwapMetaType(rawType)); // past and future
    CPPUNIT_ASSERT(!DeprecatedSwapMetaType(rawType)); // past
    CPPUNIT_ASSERT(!ReservedSwapMetaType(rawType)); // future
}

static void
checkKnownSwapMetaRawType(const RawSwapMetaType rawType)
{
    // a known raw type is either honored or ignored
    CPPUNIT_ASSERT(HonoredSwapMetaType(rawType) || IgnoredSwapMetaType(rawType));
    CPPUNIT_ASSERT(!(HonoredSwapMetaType(rawType) && IgnoredSwapMetaType(rawType)));

    if (IgnoredSwapMetaType(rawType)) {
        // an ignored raw type is either deprecated or reserved
        CPPUNIT_ASSERT(DeprecatedSwapMetaType(rawType) || ReservedSwapMetaType(rawType));
        CPPUNIT_ASSERT(!(DeprecatedSwapMetaType(rawType) && ReservedSwapMetaType(rawType)));
    } else {
        // an honored raw type is neither deprecated nor reserved
        CPPUNIT_ASSERT(!DeprecatedSwapMetaType(rawType) && !ReservedSwapMetaType(rawType));
    }
}

static void
checkTooBigSwapMetaRawType(const RawSwapMetaType rawType)
{
    // values beyond RawSwapMetaTypeTop() may be reserved for future use but
    // cannot be honored or deprecated (XXX: why not deprecated?)
    if (ReservedSwapMetaType(rawType))
        CPPUNIT_ASSERT(IgnoredSwapMetaType(rawType));
    else
        CPPUNIT_ASSERT(!IgnoredSwapMetaType(rawType));
    CPPUNIT_ASSERT(!HonoredSwapMetaType(rawType));
    CPPUNIT_ASSERT(!DeprecatedSwapMetaType(rawType));
}

static void
checkSwapMetaRawType(const RawSwapMetaType rawType)
{
    if (rawType <= RawSwapMetaTypeBottom)
        checkTooSmallSwapMetaRawType(rawType);
    else if (rawType > RawSwapMetaTypeTop())
        checkTooBigSwapMetaRawType(rawType);
    else
        checkKnownSwapMetaRawType(rawType);
}

} // namespace Store

void
testStore::testSwapMetaTypeClassification()
{
    using limits = std::numeric_limits<Store::RawSwapMetaType>;
    for (auto rawType = limits::min(); true; ++rawType) {

        Store::checkSwapMetaRawType(rawType);

        if (rawType == limits::max())
            break;
    }

    // Store::RawSwapMetaTypeTop() is documented as an honored type value
    CPPUNIT_ASSERT(Store::HonoredSwapMetaType(Store::RawSwapMetaTypeTop()));
}

