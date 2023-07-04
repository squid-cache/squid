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

class TestClpMap: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestClpMap );
    CPPUNIT_TEST( testMemoryCounter );
    CPPUNIT_TEST( testConstructor );
    CPPUNIT_TEST( testEntryCounter );
    CPPUNIT_TEST( testPutGetDelete );
    CPPUNIT_TEST( testMisses );
    CPPUNIT_TEST( testMemoryLimit );
    CPPUNIT_TEST( testTtlExpiration );
    CPPUNIT_TEST( testReplaceEntryWithShorterTtl );
    CPPUNIT_TEST( testZeroTtl );
    CPPUNIT_TEST( testNegativeTtl );
    CPPUNIT_TEST( testPurgeIsLru );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    using Map = ClpMap<std::string, int>;

    void testMemoryCounter();
    void testConstructor();
    void testEntryCounter();
    void testPutGetDelete();
    void testMisses();
    void testMemoryLimit();
    void testTtlExpiration();
    void testReplaceEntryWithShorterTtl();
    void testZeroTtl();
    void testNegativeTtl();
    void testPurgeIsLru();

    /// Generate and insert the given number of entries into the given map. Each
    /// entry is guaranteed to be inserted, but that insertion may purge other
    /// entries, including entries previously added during the same method call.
    void addSequenceOfEntriesToMap(Map &, size_t count, Map::mapped_type startWith, Map::Ttl);

    /// add (more than) enough entries to make the map full
    void fillMapWithEntries(Map &);

    /// generate and add an entry with a given value (and a matching key) to the
    /// map using map-default TTL
    void addOneEntry(Map &, Map::mapped_type);

    /// generate and add an entry with a given value, a matching key, and a
    /// given TTL to the map
    void addOneEntry(Map &, Map::mapped_type, Map::Ttl);
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestClpMap );

class SquidConfig Config;

void
TestClpMap::addSequenceOfEntriesToMap(Map &m, size_t count, const Map::mapped_type startWith, const Map::Ttl ttl)
{
    for (auto j = startWith; count; ++j, --count)
        CPPUNIT_ASSERT(m.add(std::to_string(j), j, ttl));
}

void
TestClpMap::fillMapWithEntries(Map &m)
{
    addSequenceOfEntriesToMap(m, m.memLimit() / sizeof(Map::mapped_type), 0, 10);
}

void
TestClpMap::addOneEntry(Map &m, const Map::mapped_type value)
{
    const auto key = std::to_string(value);
    CPPUNIT_ASSERT(m.add(key, value));
    CPPUNIT_ASSERT(m.get(key));
    CPPUNIT_ASSERT_EQUAL(value, *m.get(key));
}

void
TestClpMap::addOneEntry(Map &m, const Map::mapped_type value, const Map::Ttl ttl)
{
    const auto key = std::to_string(value);
    CPPUNIT_ASSERT(m.add(key, value, ttl));
    CPPUNIT_ASSERT(m.get(key));
    CPPUNIT_ASSERT_EQUAL(value, *m.get(key));
}

void
TestClpMap::setUp()
{
    squid_curtime = time(nullptr);
}

void
TestClpMap::testPutGetDelete()
{
    Map m(1024);
    addSequenceOfEntriesToMap(m, 10, 0, 10);
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
TestClpMap::testMisses()
{
    Map m(1024);
    fillMapWithEntries(m);
    const auto entriesBefore = m.entries();
    CPPUNIT_ASSERT(!m.get("not-there"));
    m.del("not-there");
    CPPUNIT_ASSERT_EQUAL(entriesBefore, m.entries());
}

void
TestClpMap::testEntryCounter()
{
    {
        Map m(10*1024*1024, 10);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), m.entries());
        addSequenceOfEntriesToMap(m, 10, 10, 10);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), m.entries());
        m.add("new-key", 0);
        CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), m.entries());
    }
    {
        Map m(1024, 5);
        addSequenceOfEntriesToMap(m, 1000, 0, 10);
        CPPUNIT_ASSERT(m.entries() < 1000);
    }
}

void
TestClpMap::testMemoryCounter()
{
    CPPUNIT_ASSERT_EQUAL(sizeof(int), static_cast<size_t>(DefaultMemoryUsage(int{})));
    CPPUNIT_ASSERT_EQUAL(sizeof(int32_t), static_cast<size_t>(DefaultMemoryUsage(int32_t{})));
    CPPUNIT_ASSERT_EQUAL(sizeof(int64_t), static_cast<size_t>(DefaultMemoryUsage(int64_t{})));
    CPPUNIT_ASSERT_EQUAL(sizeof(char), static_cast<size_t>(DefaultMemoryUsage(char{})));
    using Str = char[10];
    CPPUNIT_ASSERT_EQUAL(sizeof(Str), static_cast<size_t>(DefaultMemoryUsage(Str{})));
}

void
TestClpMap::testConstructor()
{
    const Map nilA(0);
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilA.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), nilA.entries());

    const Map nilB(0, 0);
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), nilB.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), nilB.entries());

    const Map emptyC(1);
    CPPUNIT_ASSERT_EQUAL(uint64_t(1), emptyC.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(1), emptyC.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), emptyC.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), emptyC.entries());

    const Map emptyD(1024);
    CPPUNIT_ASSERT_EQUAL(uint64_t(1024), emptyD.memLimit());
    CPPUNIT_ASSERT_EQUAL(uint64_t(1024), emptyD.freeMem());
    CPPUNIT_ASSERT_EQUAL(uint64_t(0), emptyD.memoryUsed());
    CPPUNIT_ASSERT_EQUAL(size_t(0), emptyD.entries());
}

void
TestClpMap::testMemoryLimit()
{
    const size_t initialCapacity = 1024; // bytes
    Map m(initialCapacity);
    fillMapWithEntries(m);
    const auto entriesAtInitialCapacity = m.entries();

    // check that all entries are removed if we prohibit storage of any entries
    m.setMemLimit(0);
    CPPUNIT_ASSERT_EQUAL(size_t(0), m.entries());

    // test whether the map can grow after the all-at-once purging above
    const auto increasedCapacity = initialCapacity * 2;
    m.setMemLimit(increasedCapacity);
    fillMapWithEntries(m);
    CPPUNIT_ASSERT(m.entries() > entriesAtInitialCapacity);

    // test that memory usage and entry count decrease when the map is shrinking
    // but prevent endless loops no matter how broken ClpMap implementation is
    auto iterationsLeft = m.entries();
    CPPUNIT_ASSERT(0 < iterationsLeft && iterationsLeft <= increasedCapacity);
    while (m.entries()) {
        // TODO: Check that we can still add a (smaller) entry here.

        const auto memoryUsedBefore = m.memoryUsed();
        const auto entriesBefore = m.entries();

        const auto newMemoryLimit = memoryUsedBefore/2; // may become zero
        m.setMemLimit(newMemoryLimit);

        CPPUNIT_ASSERT(m.memoryUsed() <= newMemoryLimit);
        CPPUNIT_ASSERT(m.entries() < entriesBefore);

        // the assertion below may fail if ClpMap::entries() returns bogus numbers
        CPPUNIT_ASSERT(iterationsLeft > 0);
        --iterationsLeft;
    }

    // test whether the map can grow after all that gradual purging above
    m.setMemLimit(increasedCapacity);
    fillMapWithEntries(m);
    CPPUNIT_ASSERT(m.entries() > entriesAtInitialCapacity);
}

void
TestClpMap::testTtlExpiration()
{
    {
        Map m(2048);
        addOneEntry(m, 0, 100);
        squid_curtime += 20;
        CPPUNIT_ASSERT(m.get("0")); // still fresh
        squid_curtime += 100;
        CPPUNIT_ASSERT(!m.get("0")); // has expired
    }

    {
        // same test, but using a map-specific TTL instead of entry-specific one
        Map m(2048, 100);
        addOneEntry(m, 0);
        squid_curtime += 20;
        CPPUNIT_ASSERT(m.get("0")); // still fresh
        squid_curtime += 100;
        CPPUNIT_ASSERT(!m.get("0")); // has expired
    }

    {
        // same test, but using both map-specific and entry-specific TTLs
        Map m(2048, 1);
        addOneEntry(m, 0, 100);
        squid_curtime += 20;
        CPPUNIT_ASSERT(m.get("0")); // still fresh
        squid_curtime += 100;
        CPPUNIT_ASSERT(!m.get("0")); // has expired
    }
}

void
TestClpMap::testReplaceEntryWithShorterTtl()
{
    Map m(2048);
    addOneEntry(m, 0, 100);
    addOneEntry(m, 0, 10); // same (key, value) entry but with shorter TTL
    squid_curtime += 20;
    CPPUNIT_ASSERT(!m.get("0")); // has expired

    // now the same sequence but with a time change between additions
    addOneEntry(m, 0, 100);
    squid_curtime += 200;
    addOneEntry(m, 0, 10);
    CPPUNIT_ASSERT(m.get("0")); // still fresh due to new TTL
    squid_curtime += 20;
    CPPUNIT_ASSERT(!m.get("0")); // has expired
}

void
TestClpMap::testZeroTtl()
{
    {
        Map m(2048);
        addOneEntry(m, 0, 0);
        squid_curtime += 1;
        CPPUNIT_ASSERT(!m.get("0")); // expired, we get nothing
    }

    {
        // same test, but using a map-specific TTL instead of entry-specific one
        Map m(2048, 0);
        addOneEntry(m, 0);
        squid_curtime += 1;
        CPPUNIT_ASSERT(!m.get("0")); // expired, we get nothing
    }

    {
        // same test, but using both map-specific and entry-specific TTLs
        Map m(2048, 10);
        addOneEntry(m, 0, 0);
        squid_curtime += 1;
        CPPUNIT_ASSERT(!m.get("0")); // expired, we get nothing
    }
}

void
TestClpMap::testNegativeTtl()
{
    Map m(2048);

    // we start with an ordinary-TTL entry to check that it will be purged below
    addOneEntry(m, 0, 10);

    // check that negative-TTL entries are rejected
    CPPUNIT_ASSERT(!m.add("0", 0, -1));

    // check that an attempt to add a negative-TTL entry purges the previously
    // added ordinary-TTL entry
    CPPUNIT_ASSERT(!m.get("0"));

    // check that the same entry can be re-added with a non-negative TTL
    addOneEntry(m, 0);
}

void
TestClpMap::testPurgeIsLru()
{
    Map m(2048);
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

    fillMapWithEntries(m);
    CPPUNIT_ASSERT(!m.get("0")); // removable when not recently used
}
