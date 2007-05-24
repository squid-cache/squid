
#ifndef SQUID_SRC_TEST_CACHEMANAGER_H
#define SQUID_SRC_TEST_CACHEMANAGER_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the CacheManager implementation
 */

class testCacheManager : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testCacheManager );
    CPPUNIT_TEST( testCreate );
    CPPUNIT_TEST( testRegister );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testCreate();
    void testRegister();
};

#endif

