/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_STOREHASHINDEX_H
#define SQUID_SRC_TEST_STOREHASHINDEX_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testStoreHashIndex : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStoreHashIndex );
    CPPUNIT_TEST( testStats );
    CPPUNIT_TEST( testMaxSize );
    CPPUNIT_TEST( testSearch );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testStats();
    void testMaxSize();
    void testSearch();
};

#endif

