/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_URL_H
#define SQUID_SRC_TEST_URL_H

#include "compat/cppunit.h"

/*
 * test the Anyp::Uri-related classes
 */

class TestUri: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestUri );
    CPPUNIT_TEST( testConstructScheme );
    CPPUNIT_TEST( testDefaultConstructor );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:

    void testConstructScheme();
    void testDefaultConstructor();
};

#endif

