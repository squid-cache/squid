
#ifndef SQUID_SRC_TEST_HTTP_REQUEST_H
#define SQUID_SRC_TEST_HTTP_REQUEST_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test HttpRequest
 */

class testHttpRequest : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttpRequest );
    CPPUNIT_TEST( testCreateFromUrlAndMethod );
    CPPUNIT_TEST( testCreateFromUrl );
    CPPUNIT_TEST( testIPv6HostColonBug );
    CPPUNIT_TEST( testSanityCheckStartLine );
    CPPUNIT_TEST( testParseRequestLine );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCreateFromUrlAndMethod();
    void testCreateFromUrl();
    void testIPv6HostColonBug();
    void testSanityCheckStartLine();
    void testParseRequestLine();
};

#endif

