/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTMEM_H
#define SQUID_SRC_TESTS_TESTMEM_H

#include "compat/cppunit.h"

class testMem : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testMem );
    /* note the statement here and then the actual prototype below */
    CPPUNIT_TEST( testMemPool );
    CPPUNIT_TEST( testMemProxy );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testMemPool();
    void testMemProxy();
};

#endif /* SQUID_SRC_TESTS_TESTMEM_H */

