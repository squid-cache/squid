
#ifndef SQUID_SRC_TEST_URL_H
#define SQUID_SRC_TEST_URL_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the URL class.
 */

class testURL : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testURL );
    CPPUNIT_TEST( testConstructScheme );
    CPPUNIT_TEST( testDefaultConstructor );
    CPPUNIT_TEST_SUITE_END();

public:

protected:

    void testConstructScheme();
    void testDefaultConstructor();
};

#endif

