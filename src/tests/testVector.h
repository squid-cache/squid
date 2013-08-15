#ifndef SQUID_SRC_TESTS_TESTVECTOR_H
#define SQUID_SRC_TESTS_TESTVECTOR_H

#include <cppunit/extensions/HelperMacros.h>

/*
 * A test case that is designed to produce
 * example errors and failures
 *
 */

class testVector : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testVector );
    CPPUNIT_TEST( all );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void all();
};

#endif
