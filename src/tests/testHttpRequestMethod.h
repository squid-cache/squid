/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_HTTP_REQUEST_METHOD_H
#define SQUID_SRC_TEST_HTTP_REQUEST_METHOD_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test HttpRequestMethod
 */

class testHttpRequestMethod : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttpRequestMethod );
    CPPUNIT_TEST( testAssignFrommethod_t );
    CPPUNIT_TEST( testConstructmethod_t );
    CPPUNIT_TEST( testConstructCharStart );
    CPPUNIT_TEST( testConstructCharStartEnd );
    CPPUNIT_TEST( testDefaultConstructor );
    CPPUNIT_TEST( testEqualmethod_t );
    CPPUNIT_TEST( testNotEqualmethod_t );
    CPPUNIT_TEST( testImage );
    CPPUNIT_TEST( testStream );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testAssignFrommethod_t();
    void testConstructmethod_t();
    void testConstructCharStart();
    void testConstructCharStartEnd();
    void testImage();
    void testDefaultConstructor();
    void testEqualmethod_t();
    void testNotEqualmethod_t();
    void testStream();
};

#endif

