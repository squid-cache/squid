#ifndef SQUID_SRC_TESTS_TESTHTTPPARSER_H
#define SQUID_SRC_TESTS_TESTHTTPPARSER_H

#include <cppunit/extensions/HelperMacros.h>

class testHttpParser : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttpParser );
    CPPUNIT_TEST( testParseRequestLineTerminators );
    CPPUNIT_TEST( testParseRequestLineMethods );
    CPPUNIT_TEST( testParseRequestLineProtocols );
    CPPUNIT_TEST( testParseRequestLineStrange );
    CPPUNIT_TEST( testParseRequestLineInvalid );
    CPPUNIT_TEST_SUITE_END();

protected:
    void globalSetup(); // MemPools init etc.

    // request-line unit tests
    void testParseRequestLineTerminators(); // terminator detection correct
    void testParseRequestLineMethods();     // methoid detection correct
    void testParseRequestLineProtocols();   // protocol tokens handled correctly
    void testParseRequestLineStrange();     // strange but valid lines accepted
    void testParseRequestLineInvalid();     // rejection of invalid lines happens
};

#endif
