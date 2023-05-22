/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "mem/Allocator.h"
#include "mem/Pool.h"
#include "unitTestMain.h"

#include <iostream>
#include <stdexcept>

class TestMem : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestMem);
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST(testMemPool);
    CPPUNIT_TEST(testMemProxy);
    CPPUNIT_TEST_SUITE_END();

public:
protected:
    void testMemPool();
    void testMemProxy();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestMem);

class SomethingToAlloc
{
public:
    int aValue;
};

class MoreToAlloc
{
    MEMPROXY_CLASS(MoreToAlloc);

public:
    int aValue = 0;
};

void
TestMem::testMemPool()
{
    const auto Pool = memPoolCreate("Test Pool", sizeof(SomethingToAlloc));
    CPPUNIT_ASSERT(Pool);

    auto *something = static_cast<SomethingToAlloc *>(Pool->alloc());
    CPPUNIT_ASSERT(something);
    CPPUNIT_ASSERT_EQUAL(something->aValue, 0);
    something->aValue = 5;
    Pool->freeOne(something);

    // Pool should use the FreeList to allocate next object
    auto *otherthing = static_cast<SomethingToAlloc *>(Pool->alloc());
    CPPUNIT_ASSERT_EQUAL(otherthing, something);
    CPPUNIT_ASSERT_EQUAL(otherthing->aValue, 0);
    Pool->freeOne(otherthing);

    delete Pool;
}

void
TestMem::testMemProxy()
{
    auto *something = new MoreToAlloc;
    CPPUNIT_ASSERT(something);
    CPPUNIT_ASSERT_EQUAL(something->aValue, 0);
    something->aValue = 5;
    delete something;

    // The MEMPROXY pool should use its FreeList to allocate next object
    auto *otherthing = new MoreToAlloc;
    CPPUNIT_ASSERT_EQUAL(otherthing, something);
    CPPUNIT_ASSERT_EQUAL(otherthing->aValue, 0);
}

