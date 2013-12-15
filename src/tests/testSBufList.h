#ifndef SQUID_SRC_TEST_TESTSBUF_H
#define SQUID_SRC_TEST_TESTSBUF_H

#include <cppunit/extensions/HelperMacros.h>

#include "OutOfBoundsException.h"

class testSBufList : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testSBufList );
    CPPUNIT_TEST( testSBufListMembership );
    CPPUNIT_TEST( testSBufListJoin );
    CPPUNIT_TEST_SUITE_END();
protected:
    void testSBufListMembership();
    void testSBufListJoin();
};

#endif
