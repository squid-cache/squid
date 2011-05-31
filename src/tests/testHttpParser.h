#ifndef SQUID_SRC_TESTS_TESTHTTPPARSER_H
#define SQUID_SRC_TESTS_TESTHTTPPARSER_H

#include <cppunit/extensions/HelperMacros.h>

class testHttpParser : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttpParser );
    CPPUNIT_TEST( testParseRequestLine );
    CPPUNIT_TEST_SUITE_END();

protected:
    void globalSetup(); // MemPools init etc.
    void testParseRequestLine();
};

#endif
