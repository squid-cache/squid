
#ifndef SQUID_SRC_TEST_STRING_H
#define SQUID_SRC_TEST_STRING_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testString : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testString );
    CPPUNIT_TEST( testCmpDefault );
    CPPUNIT_TEST( testCmpEmptyString );
    CPPUNIT_TEST( testCmpNotEmptyDefault );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCmpDefault();
    void testCmpEmptyString();
    void testCmpNotEmptyDefault();
};

#endif

