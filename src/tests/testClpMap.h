/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_TESTCLPMAP_H
#define SQUID_BASE_TESTCLPMAP_H

#include "compat/cppunit.h"
#include "base/ClpMap.h"

class testClpMap: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testClpMap );
    CPPUNIT_TEST( testMemoryCounter );
    CPPUNIT_TEST( testConstructor );
    CPPUNIT_TEST( testEntries );
    CPPUNIT_TEST( testPutGetDelete );
    CPPUNIT_TEST( testSetMemLimit );
    CPPUNIT_TEST( testTtlExpiration );
    CPPUNIT_TEST_SUITE_END();

protected:
    using TestMap = ClpMap<std::string, int>;

    // add a standard set of elements to a map
    void addData(TestMap &, int count, int startWith, TestMap::Ttl);
    void testMemoryCounter();
    void testConstructor();
    void testEntries();
    void testPutGetDelete();
    void testSetMemLimit();
    void testTtlExpiration();

public:
    void setUp() override;
};

#endif /* SQUID_BASE_TESTCLPMAP_H */

