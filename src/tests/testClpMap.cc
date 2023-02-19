/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SquidConfig.h"
#include "testClpMap.h"
#include "unitTestMain.h"

#include <ctime>

CPPUNIT_TEST_SUITE_REGISTRATION( testClpMap );

class SquidConfig Config;

void
testClpMap::addData(TestMap &m, int count, int startWith, TestMap::Ttl ttl)
{
    for (auto j = startWith; j < startWith + count; ++j)
    {
        CPPUNIT_ASSERT_EQUAL(true, m.add(std::to_string(j), j, ttl));
    }
}


void
testClpMap::setUp()
{
    squid_curtime = time(nullptr);
}

void
testClpMap::testPutGetDelete()
{
    TestMap m(1024);
    addData(m, 10, 0, 10);
    CPPUNIT_ASSERT_EQUAL(static_cast<const int *>(nullptr), m.get("notthere"));
    CPPUNIT_ASSERT_EQUAL(1, *(m.get("1")));
    CPPUNIT_ASSERT_EQUAL(9, *(m.get("9")));
    m.add("1", 99);
    CPPUNIT_ASSERT_EQUAL(99, *(m.get("1")));
    m.del("1");
    CPPUNIT_ASSERT_EQUAL(static_cast<const int *>(nullptr), m.get("1"));
}

void testClpMap::testEntries()
{
    {
        TestMap m(10*1024*1024, 10);
        addData(m, 10, 10, 10);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), m.entries());
        m.add("foo", 0);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), m.entries());
    }
    {
        TestMap m(1024, 5);
        addData(m, 1000, 0, 10);
        CPPUNIT_ASSERT(m.entries() < 1000);
    }
}

void
testClpMap::testMemoryCounter()
{
    CPPUNIT_ASSERT_EQUAL(sizeof(int), static_cast<size_t>(DefaultMemoryUsage(int())));
    CPPUNIT_ASSERT_EQUAL(sizeof(int32_t), static_cast<size_t>(DefaultMemoryUsage(int32_t())));
    CPPUNIT_ASSERT_EQUAL(sizeof(int64_t), static_cast<size_t>(DefaultMemoryUsage(int64_t())));
    CPPUNIT_ASSERT_EQUAL(sizeof(char), static_cast<size_t>(DefaultMemoryUsage(char())));
    char str[10];
    CPPUNIT_ASSERT_EQUAL(sizeof(str), static_cast<size_t>(DefaultMemoryUsage(str)));
    CPPUNIT_ASSERT_EQUAL(sizeof(std::string), static_cast<size_t>(DefaultMemoryUsage(std::string())));
}

void
testClpMap::testConstructor()
{
    TestMap nilA(0);
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), nilA.entries());

    TestMap nilB(0, 0);
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), nilB.entries());

    TestMap emptyC(1);
    CPPUNIT_ASSERT_EQUAL(uint64_t(1), emptyC.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(1), emptyC.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), emptyC.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), emptyC.entries());

    TestMap emptyD(1024);
    CPPUNIT_ASSERT_EQUAL(uint64_t(1024), emptyD.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(1024), emptyD.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), emptyD.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), emptyD.entries());
}

void
testClpMap::testSetMemLimit()
{
    TestMap m(2048);
    addData(m, 1000, 0, 10);
    auto testEntriesBefore = m.entries();
    m.setMemLimit(1024);
    CPPUNIT_ASSERT(testEntriesBefore > m.entries());
}

#include <iostream>
void
testClpMap::testTtlExpiration()
{
    TestMap m(2048);
    m.add(std::to_string(1), 1, 10);
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), m.entries());
    CPPUNIT_ASSERT(static_cast<const int *>(nullptr)!=m.get("1"));
    squid_curtime += 100;
    // "1" should have expired
    CPPUNIT_ASSERT(!m.get("1"));
}

