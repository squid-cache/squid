/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LIB_TEST_RFC1738_H
#define SQUID_LIB_TEST_RFC1738_H

#include <cppunit/extensions/HelperMacros.h>

/**
 * Test the URL coder RFC 1738 Engine
 */
class testRFC1738 : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testRFC1738 );
    CPPUNIT_TEST( testUrlDecode );
    CPPUNIT_TEST( testUrlEncode );

    CPPUNIT_TEST( PercentZeroNullDecoding );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testUrlDecode();
    void testUrlEncode();

    // bugs.
    void PercentZeroNullDecoding();
};

#endif /* SQUID_LIB_TEST_RFC1738_H */

