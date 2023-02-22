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
testClpMap::addSequenceOfElementsToMap(TestMap &m, size_t count, const TestMap::mapped_type startWith, const TestMap::Ttl ttl)
{
    for (auto j = startWith; count; ++j, --count)
    {
        CPPUNIT_ASSERT(m.add(std::to_string(j), j, ttl));
    }
}

void
testClpMap::fillMapWithElements(TestMap &m, TestMap::Ttl ttl)
{
    addSequenceOfElementsToMap(m, m.memLimit() / sizeof(TestMap::mapped_type), 0, ttl);
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
    addSequenceOfElementsToMap(m, 10, 0, 10);
    CPPUNIT_ASSERT(!m.get("notthere"));
    CPPUNIT_ASSERT(m.get("1")); // we get something
    CPPUNIT_ASSERT_EQUAL(1, *(m.get("1"))); // we get what we put in
    CPPUNIT_ASSERT(m.get("9"));
    CPPUNIT_ASSERT_EQUAL(9, *(m.get("9")));
    m.add("1", 99);
    CPPUNIT_ASSERT(m.get("1"));
    CPPUNIT_ASSERT_EQUAL(99, *(m.get("1")));
    m.del("1");
    CPPUNIT_ASSERT(!m.get("1")); // entry has been cleared
}

void
testClpMap::testEntries()
{
    {
        TestMap m(10*1024*1024, 10);
        addSequenceOfElementsToMap(m, 10, 10, 10);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), m.entries());
        m.add("foo", 0);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), m.entries());
    }
    {
        TestMap m(1024, 5);
        addSequenceOfElementsToMap(m, 1000, 0, 10);
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
    const TestMap nilA(0);
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), nilA.entries());

    const TestMap nilB(0, 0);
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), nilB.entries());

    const TestMap emptyC(1);
    CPPUNIT_ASSERT_EQUAL(uint64_t(1), emptyC.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(1), emptyC.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), emptyC.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), emptyC.entries());

    const TestMap emptyD(1024);
    CPPUNIT_ASSERT_EQUAL(uint64_t(1024), emptyD.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(1024), emptyD.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), emptyD.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), emptyD.entries());
}

void
testClpMap::testSetMemLimit()
{
    TestMap m(2048);
    // overflow the map with entries to make sure it has lots of entries to purge below
    fillMapWithElements(m, 10);
    auto testEntriesBefore = m.entries();
    CPPUNIT_ASSERT(testEntriesBefore > 0);

    m.setMemLimit(m.memoryUsed() / 2);
    auto entriesAfterPurge = m.entries();
    CPPUNIT_ASSERT(testEntriesBefore > entriesAfterPurge);

    m.setMemLimit(m.memLimit() * 2);
    // overflow the map with entries again to make sure it can grow after purging
    fillMapWithElements(m, 10);
    CPPUNIT_ASSERT(entriesAfterPurge < m.entries());

    // progressively shrink to size 0, checking that the number of
    // entries decreases each time
    testEntriesBefore = m.entries();
    const auto singleEntrySizeEstimate = *TestMap::MemoryCountedFor("0", 0) + 10;
    while (m.memoryUsed() > singleEntrySizeEstimate) {
        m.setMemLimit(m.memoryUsed() / 2);
        entriesAfterPurge = m.entries();
        CPPUNIT_ASSERT(testEntriesBefore > entriesAfterPurge);
        CPPUNIT_ASSERT(entriesAfterPurge > 0);
        testEntriesBefore = entriesAfterPurge;
    }

    // set size to 0, all entries should have been removed
    m.setMemLimit(0);
    CPPUNIT_ASSERT_EQUAL(size_t(0), m.entries());

    // test that memory used decreases when shrinking
    size_t curLimit = 10240;
    size_t lastMemoryUsed;
    m.setMemLimit(curLimit);
    fillMapWithElements(m, 1000);
    lastMemoryUsed = m.memoryUsed();
    while (curLimit > 1024) // stop at any practical size
    {
        CPPUNIT_ASSERT(m.memoryUsed() < curLimit);
        CPPUNIT_ASSERT(m.memoryUsed() <= lastMemoryUsed);
        // also check that we can still add entries - evicting old ones if needed
        CPPUNIT_ASSERT(m.add(std::to_string(curLimit+1000), 1, 10));
        CPPUNIT_ASSERT_EQUAL(1, *m.get(std::to_string(curLimit + 1000)));
        curLimit /= 2;
        lastMemoryUsed = m.memoryUsed();
        m.setMemLimit(curLimit);
    }
}

void
testClpMap::testTtlExpiration()
{
    TestMap m(2048);
    m.add(std::to_string(1), 1, 10);
    CPPUNIT_ASSERT(m.get("1"));
    squid_curtime += 100;
    // "1" should have expired
    CPPUNIT_ASSERT(!m.get("1"));
}

void
testClpMap::testReplaceEntryWithShorterTtl()
{
    TestMap m(2048);
    addSequenceOfElementsToMap(m, 1, 0, 100);
    CPPUNIT_ASSERT(m.get("0")); // successfully added one element
    squid_curtime += 20;
    CPPUNIT_ASSERT(m.get("0")); // hasn't expired yet
    squid_curtime += 100;
    CPPUNIT_ASSERT(!m.get("0")); // has expired

    addSequenceOfElementsToMap(m, 1, 0, 100);
    addSequenceOfElementsToMap(m, 1, 0, 10); // replaced element with same but shorter ttl
    squid_curtime += 20;
    CPPUNIT_ASSERT(!m.get("0")); // should have expired
}

void
testClpMap::testEntriesWithZeroTtl()
{
    TestMap m(2048);
    addSequenceOfElementsToMap(m, 1, 0, 0);
    CPPUNIT_ASSERT(m.get("0")); // we get something
    squid_curtime += 1;
    CPPUNIT_ASSERT(!m.get("0")); // expired, we get nothing
}

void
testClpMap::testEntriesWithNegativeTtl()
{
    TestMap m(2048);
    CPPUNIT_ASSERT(!m.add("0", 0, -1)); // failure on insertion
    CPPUNIT_ASSERT(!m.get("0"));  // we get nothing
    CPPUNIT_ASSERT(m.add("0", 1, 0));
    CPPUNIT_ASSERT(m.get("0"));  // we get something
    CPPUNIT_ASSERT(!m.add("0", 2, -1));  // failure on insertion
    CPPUNIT_ASSERT(!m.get("0"));  // we get nothing
}

void
testClpMap::testPurgeIsLRU()
{
    TestMap m(2048);
    // TODO: once we have ClpMap iterators we can inspect the contents instead
    for (int j = 0; j < 10; ++j)
        CPPUNIT_ASSERT(m.add(std::to_string(j), j, 10));
    // now overflow the map while keeping "0" the Least Recently Used
    for (int j = 100; j < 1000; ++j) {
        CPPUNIT_ASSERT(m.add(std::to_string(j), j, 10));
        CPPUNIT_ASSERT(m.get("0"));
    }
    // these should have been aged out
    CPPUNIT_ASSERT(!m.get("1"));
    CPPUNIT_ASSERT(!m.get("2"));
    CPPUNIT_ASSERT(!m.get("3"));
    CPPUNIT_ASSERT(!m.get("4"));

    fillMapWithElements(m, 10);
    CPPUNIT_ASSERT(!m.get("0")); // removable when not recently used
}
