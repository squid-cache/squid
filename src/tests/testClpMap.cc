/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "testClpMap.h"
#include "unitTestMain.h"

#include "SquidConfig.h"

#include <iostream>


CPPUNIT_TEST_SUITE_REGISTRATION( testClpMap );

class SquidConfig Config;

void
testClpMap::addData(testMap &m, int numElems, int base)
{
    for (int j = base; j < base + numElems; ++j ) {
        CPPUNIT_ASSERT_EQUAL(true, m.add(std::to_string(j), j));
        std::cout << '.';
    }
}

void
testClpMap::PutAndGet()
{
    testMap m(10);
    addData(m, 10);
}

void
testClpMap::Entries()
{
    {
        testMap m(100, 10);
        addData(m, 10, 10);
        std::cout << m.entries() << std::endl;
        m.add("foo", 0, 10);
        std::cout << m.entries() << std::endl;
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), m.entries());
    }
    {
        testMap m(5);
        addData(m, 10);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(5), m.entries());
    }
}