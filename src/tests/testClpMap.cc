/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/ClpMap.h"
#include "compat/cppunit.h"
#include "SquidConfig.h"
#include "unitTestMain.h"

#include <ctime>

class testClpMap: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testClpMap );
    CPPUNIT_TEST( testMemoryCounter );
    CPPUNIT_TEST( testConstructor );
    CPPUNIT_TEST( testEntries );
    CPPUNIT_TEST( testPutGetDelete );
    CPPUNIT_TEST( testMemoryLimit );
    CPPUNIT_TEST( testTtlExpiration );
    CPPUNIT_TEST( testReplaceEntryWithShorterTtl );
    CPPUNIT_TEST( testEntriesWithZeroTtl );
    CPPUNIT_TEST( testEntriesWithNegativeTtl );
    CPPUNIT_TEST( testPurgeIsLRU );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    using TestMap = ClpMap<std::string, int>;

    void testMemoryCounter();
    void testConstructor();
    void testEntries();
    void testPutGetDelete();
    void testMemoryLimit();
    void testTtlExpiration();
    void testReplaceEntryWithShorterTtl();
    void testEntriesWithZeroTtl();
    void testEntriesWithNegativeTtl();
    void testPurgeIsLRU();

    /// Generate and insert the given number of elements into the given map.
    /// Each entry is guaranteed to be inserted, but that insertion may purge other entries,
    /// including entries previously added during the same method call
    void addSequenceOfElementsToMap(TestMap &, size_t count, TestMap::mapped_type startWith, TestMap::Ttl);

    /// add (more than) enough elements to make the map full
    void fillMapWithElements(TestMap &);

    /// generate and add an entry with a given value (and a matching key) to the map
    void addOneEntry(TestMap &, TestMap::mapped_type, TestMap::Ttl = std::numeric_limits<TestMap::Ttl>::max());
};

CPPUNIT_TEST_SUITE_REGISTRATION( testClpMap );

class SquidConfig Config;

void
testClpMap::addSequenceOfElementsToMap(TestMap &m, size_t count, const TestMap::mapped_type startWith, const TestMap::Ttl ttl)
{
    for (auto j = startWith; count; ++j, --count)
        CPPUNIT_ASSERT(m.add(std::to_string(j), j, ttl));
}

void
testClpMap::fillMapWithElements(TestMap &m)
{
    addSequenceOfElementsToMap(m, m.memLimit() / sizeof(TestMap::mapped_type), 0, 10);
}

void
testClpMap::addOneEntry(TestMap &m, const TestMap::mapped_type value, const TestMap::Ttl ttl)
{
    const auto key = std::to_string(value);
    CPPUNIT_ASSERT(m.add(key, value, ttl));
    CPPUNIT_ASSERT(m.get(key));
    CPPUNIT_ASSERT_EQUAL(value, *m.get(key));
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
testClpMap::testMemoryLimit()
{
    const size_t initialCapacity = 1024; // bytes
    TestMap m(initialCapacity);
    fillMapWithElements(m);
    const auto entriesAtInitialCapacity = m.entries();

    // check that all entries are removed if we prohibit storage of any entries
    m.setMemLimit(0);
    CPPUNIT_ASSERT_EQUAL(size_t(0), m.entries());

    // test whether the map can grow after the all-at-once purging above
    m.setMemLimit(initialCapacity * 2);
    fillMapWithElements(m);
    CPPUNIT_ASSERT(m.entries() > entriesAtInitialCapacity);

    // test that memory usage and entry count decrease when the map is shrinking
    while (m.entries()) {
        // also check that we can still add entries, evicting old ones if needed
        // (at least as long as there is at least one entry in the map)
        addOneEntry(m, 0);

        const auto memoryUsedBefore = m.memoryUsed();
        const auto entriesBefore = m.entries();

        m.setMemLimit(memoryUsedBefore/2);

        CPPUNIT_ASSERT(m.memoryUsed() < memoryUsedBefore);
        CPPUNIT_ASSERT(m.entries() < entriesBefore);
    }

    // test whether the map can grow after all that gradual purging above
    m.setMemLimit(initialCapacity * 2);
    fillMapWithElements(m);
    CPPUNIT_ASSERT(m.entries() > entriesAtInitialCapacity);
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
    addOneEntry(m, 0, 100);
    squid_curtime += 20;
    CPPUNIT_ASSERT(m.get("0")); // hasn't expired yet
    squid_curtime += 100;
    CPPUNIT_ASSERT(!m.get("0")); // has expired

    addOneEntry(m, 0, 100);
    addOneEntry(m, 0, 10); // replaced element with same but shorter ttl
    squid_curtime += 20;
    CPPUNIT_ASSERT(!m.get("0")); // should have expired
}

void
testClpMap::testEntriesWithZeroTtl()
{
    TestMap m(2048);
    addOneEntry(m, 0, 0);
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
        addOneEntry(m, j);
    // now overflow the map while keeping "0" the Least Recently Used
    for (int j = 100; j < 1000; ++j) {
        addOneEntry(m, j);
        CPPUNIT_ASSERT(m.get("0"));
    }
    // these should have been aged out
    CPPUNIT_ASSERT(!m.get("1"));
    CPPUNIT_ASSERT(!m.get("2"));
    CPPUNIT_ASSERT(!m.get("3"));
    CPPUNIT_ASSERT(!m.get("4"));

    fillMapWithElements(m);
    CPPUNIT_ASSERT(!m.get("0")); // removable when not recently used
}
