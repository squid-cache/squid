/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTURISCHEME_H
#define SQUID_SRC_TESTS_TESTURISCHEME_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test UriScheme
 */

class testUriScheme : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testUriScheme );
    CPPUNIT_TEST( testAssignFromprotocol_t );
    CPPUNIT_TEST( testCastToprotocol_t );
    CPPUNIT_TEST( testConstructprotocol_t );
#if 0

    CPPUNIT_TEST( testConstructCharStart );
    CPPUNIT_TEST( testConstructCharStartEnd );
#endif

    CPPUNIT_TEST( testDefaultConstructor );
    CPPUNIT_TEST( testEqualprotocol_t );
    CPPUNIT_TEST( testNotEqualprotocol_t );
    CPPUNIT_TEST( testC_str );
    CPPUNIT_TEST( testStream );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testAssignFromprotocol_t();
    void testCastToprotocol_t();
    void testConstructprotocol_t();
#if 0

    void testConstructCharStart();
    void testConstructCharStartEnd();
#endif

    void testC_str();
    void testDefaultConstructor();
    void testEqualprotocol_t();
    void testNotEqualprotocol_t();
    void testStream();
};

#endif

