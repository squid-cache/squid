
#ifndef SQUID_SRC_TEST_STORE_H
#define SQUID_SRC_TEST_STORE_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the store framework
 */

class testStore : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStore );
    CPPUNIT_TEST( testSetRoot );
    CPPUNIT_TEST( testUnsetRoot );
    CPPUNIT_TEST( testStats );
    CPPUNIT_TEST( testMaxSize );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testSetRoot();
    void testUnsetRoot();
    void testStats();
    void testMaxSize();
};

#endif

