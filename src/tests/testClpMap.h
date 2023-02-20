/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_TESTCLPMAP_H
#define SQUID_BASE_TESTCLPMAP_H

#include "base/ClpMap.h"
#include "compat/cppunit.h"

class testClpMap: public CPPUNIT_NS::TestFixture
{
private:
    CPPUNIT_TEST_SUITE(testClpMap);
    CPPUNIT_TEST( testMemoryCounter );
    CPPUNIT_TEST( testConstructor );
    CPPUNIT_TEST( testEntries );
    CPPUNIT_TEST( testPutGetDelete );
    CPPUNIT_TEST( testSetMemLimit );
    CPPUNIT_TEST( testTtlExpiration );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    using TestMap = ClpMap<std::string, int>;

    // add a standard set of elements to a map
    void addSequenceOfElementsToMap(TestMap &, int count, int startWith, TestMap::Ttl);
    void testMemoryCounter();
    void testConstructor();
    void testEntries();
    void testPutGetDelete();
    void testSetMemLimit();
    void testTtlExpiration();

};

#endif /* SQUID_BASE_TESTCLPMAP_H */

