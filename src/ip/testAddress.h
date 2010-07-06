#ifndef SQUID_SRC_TEST_IPADDRESS_H
#define SQUID_SRC_TEST_IPADDRESS_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the IP storage type
 */

class testIpAddress : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testIpAddress );
    CPPUNIT_TEST( testDefaults );
    CPPUNIT_TEST( testInAddrConstructor );
#if USE_IPV6
    CPPUNIT_TEST( testInAddr6Constructor );
#endif
    CPPUNIT_TEST( testSockAddrConstructor );
#if USE_IPV6
    CPPUNIT_TEST( testSockAddr6Constructor );
#endif
    CPPUNIT_TEST( testHostentConstructor );
    CPPUNIT_TEST( testStringConstructor );
    CPPUNIT_TEST( testCopyConstructor );
    CPPUNIT_TEST( testSetEmpty );
    CPPUNIT_TEST( testBooleans );
    CPPUNIT_TEST( testAddrInfo );
    CPPUNIT_TEST( testNtoA );
    CPPUNIT_TEST( testToURL_fromInAddr );
    CPPUNIT_TEST( testToURL_fromSockAddr );
    CPPUNIT_TEST( testGetReverseString );
    CPPUNIT_TEST( testMasking );

    CPPUNIT_TEST( testBugNullingDisplay );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testDefaults();

    void testInAddrConstructor();
#if USE_IPV6
    void testInAddr6Constructor();
#endif
    void testSockAddrConstructor();
#if USE_IPV6
    void testSockAddr6Constructor();
#endif
    void testHostentConstructor();
    void testStringConstructor();
    void testCopyConstructor();

    void testSetEmpty();
    void testBooleans();

    void testAddrInfo();

    void testNtoA();
    void testToURL_fromInAddr();
    void testToURL_fromSockAddr();
    void testGetReverseString();
    void testMasking();

    // bugs.
    void testBugNullingDisplay();

};

#endif /* SQUID_SRC_TEST_IPADDRESS_H */
