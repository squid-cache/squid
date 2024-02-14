/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTSTOREHASHINDEX_H
#define SQUID_SRC_TESTS_TESTSTOREHASHINDEX_H

#include "compat/cppunit.h"

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

#endif /* SQUID_SRC_TESTS_TESTSTOREHASHINDEX_H */

