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
    CPPUNIT_TEST_SUITE(testClpMap);
    // CPPUNIT_TEST(  );
    CPPUNIT_TEST(testMemoryCounter);
    CPPUNIT_TEST(testConstructor);
    CPPUNIT_TEST(Entries);
    CPPUNIT_TEST_SUITE_END();

protected:
    using testMap = ClpMap<std::string, int>;

    // add a standard set of key-values to the map, up to numElems
    // the keys and values will start at base and count up numElems
    void addData(testMap &m, int numElems = 10, int base = 0);
    void testMemoryCounter();
    void testConstructor();
    void Entries();
    void PutAndGet();
public:
    void setUp() override;
};

#endif /* SQUID_BASE_TESTCLPMAP_H */