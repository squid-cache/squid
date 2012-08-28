
#ifndef SQUID_LIB_TEST_ARRAY_H
#define SQUID_LIB_TEST_ARRAY_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * A test case that is designed to produce
 * example errors and failures
 *
 */

class testArray : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testArray );
    CPPUNIT_TEST( all );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void all();
};

#endif

