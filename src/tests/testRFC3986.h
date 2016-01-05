/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LIB_TEST_RFC3986_H
#define SQUID_LIB_TEST_RFC3986_H

#include <cppunit/extensions/HelperMacros.h>

/**
 * Test the URL coder RFC 3986 Engine
 */
class testRFC3986 : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testRFC3986 );
    CPPUNIT_TEST( testUrlDecode );
    CPPUNIT_TEST( testUrlEncode );
    CPPUNIT_TEST( PercentZeroNullDecoding );
    CPPUNIT_TEST( testPerformance );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testUrlDecode();
    void testUrlEncode();

    // bugs.
    void PercentZeroNullDecoding();
    void testPerformance();
};

#endif /* SQUID_LIB_TEST_RFC3986_H */

