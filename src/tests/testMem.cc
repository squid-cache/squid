/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem/forward.h"
#include "mem/Pool.h"
#include "tests/testMem.h"
#include "unitTestMain.h"

#include <iostream>
#include <stdexcept>

CPPUNIT_TEST_SUITE_REGISTRATION( testMem );

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
testMem::testMemPool()
{
    MemAllocator *Pool = memPoolCreate("Test Pool", sizeof(SomethingToAlloc));
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
testMem::testMemProxy()
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

