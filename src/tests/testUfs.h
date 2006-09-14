
#ifndef SQUID_SRC_TEST_STORECONTROLLER_H
#define SQUID_SRC_TEST_STORECONTROLLER_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testUfs : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testUfs );
    CPPUNIT_TEST( testUfsSearch );
    CPPUNIT_TEST( testUfsDefaultEngine );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void commonInit();
    void testUfsSearch();
    void testUfsDefaultEngine();
};

#endif

