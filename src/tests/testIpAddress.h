/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_IPADDRESS_H
#define SQUID_SRC_TEST_IPADDRESS_H

#include "compat/cppunit.h"

/*
 * test the IP storage type
 */

class testIpAddress : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testIpAddress );
    CPPUNIT_TEST( testDefaults );
    CPPUNIT_TEST( testInAddrConstructor );
    CPPUNIT_TEST( testInAddr6Constructor );
    CPPUNIT_TEST( testSockAddrConstructor );
    CPPUNIT_TEST( testSockAddr6Constructor );
    CPPUNIT_TEST( testHostentConstructor );
    CPPUNIT_TEST( testStringConstructor );
    CPPUNIT_TEST( testCopyConstructor );
    CPPUNIT_TEST( testsetEmpty );
    CPPUNIT_TEST( testBooleans );
    CPPUNIT_TEST( testAddrInfo );
    CPPUNIT_TEST( testtoStr );
    CPPUNIT_TEST( testtoUrl_fromInAddr );
    CPPUNIT_TEST( testtoUrl_fromSockAddr );
    CPPUNIT_TEST( testgetReverseString );
    CPPUNIT_TEST( testMasking );

    CPPUNIT_TEST( testBugNullingDisplay );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testDefaults();

    void testInAddrConstructor();
    void testInAddr6Constructor();
    void testSockAddrConstructor();
    void testSockAddr6Constructor();
    void testHostentConstructor();
    void testStringConstructor();
    void testCopyConstructor();

    void testsetEmpty();
    void testBooleans();

    void testAddrInfo();

    void testtoStr();
    void testtoUrl_fromInAddr();
    void testtoUrl_fromSockAddr();
    void testgetReverseString();
    void testMasking();

    // bugs.
    void testBugNullingDisplay();

};

#endif /* SQUID_SRC_TEST_IPADDRESS_H */

