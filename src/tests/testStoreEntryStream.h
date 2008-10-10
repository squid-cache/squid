
#ifndef SQUID_SRC_TEST_STORE_ENTRY_STREAM_H
#define SQUID_SRC_TEST_STORE_ENTRY_STREAM_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * test StoreEntryStream
 */

class testStoreEntryStream : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStoreEntryStream );
    CPPUNIT_TEST( testGetStream );
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();

protected:
    void testGetStream();
};

#endif

