
#ifndef SQUID_SRC_TEST_STORECONTROLLER_H
#define SQUID_SRC_TEST_STORECONTROLLER_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testCoss : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testCoss );
    CPPUNIT_TEST( testCossCreate );
    CPPUNIT_TEST( testCossSearch );
    CPPUNIT_TEST( testDefaultEngine );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void commonInit();
    void testCossCreate();
    void testCossSearch();
    void testDefaultEngine();
};

#endif

