/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTSTORE_H
#define SQUID_SRC_TESTS_TESTSTORE_H

#include "compat/cppunit.h"

/*
 * test the store framework
 */

class TestStore: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestStore );
    CPPUNIT_TEST( testSwapMetaTypeClassification );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testSwapMetaTypeClassification();
};

#endif /* SQUID_SRC_TESTS_TESTSTORE_H */

