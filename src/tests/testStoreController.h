
#ifndef SQUID_SRC_TEST_STORECONTROLLER_H
#define SQUID_SRC_TEST_STORECONTROLLER_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testStoreController : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStoreController );
    CPPUNIT_TEST( testStats );
    CPPUNIT_TEST( testMaxSize );
    CPPUNIT_TEST( testSearch );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testStats();
    void testMaxSize();
    void testSearch();
};

#endif

