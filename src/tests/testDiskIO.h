
#ifndef SQUID_SRC_TEST_DISKIO_H
#define SQUID_SRC_TEST_DISKIO_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test the DiskIO framework
 */

class testDiskIO : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testDiskIO );
    CPPUNIT_TEST( testFindDefault );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testFindDefault();
};

#endif

