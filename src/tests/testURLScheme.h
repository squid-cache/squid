
#ifndef SQUID_SRC_TEST_URL_SCHEME_H
#define SQUID_SRC_TEST_URL_SCHEME_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test URLScheme
 */

class testURLScheme : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testURLScheme );
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
    CPPUNIT_TEST( testConst_str );
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

    void testConst_str();
    void testDefaultConstructor();
    void testEqualprotocol_t();
    void testNotEqualprotocol_t();
    void testStream();
};

#endif

