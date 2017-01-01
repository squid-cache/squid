/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTNETDB_H
#define SQUID_SRC_TESTS_TESTNETDB_H

#include <cppunit/extensions/HelperMacros.h>

class testNetDb : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testNetDb );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testConstruct );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testConstruct();
};

#endif /* SQUID_SRC_TESTS_TESTNETDB_H */

