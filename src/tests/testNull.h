
#ifndef SQUID_SRC_TEST_STORECONTROLLER_H
#define SQUID_SRC_TEST_STORECONTROLLER_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testNull : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testNull );
    CPPUNIT_TEST( testNullCreate );
    CPPUNIT_TEST( testNullSearch );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void commonInit();
    void testNullCreate();
    void testNullSearch();
};

#endif

