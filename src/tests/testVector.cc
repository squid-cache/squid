#define SQUID_UNIT_TEST 1
#include "squid.h"
#include "base/Vector.h"
#include "tests/testVector.h"

#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( testVector );

void testVector::all()
{
    CPPUNIT_ASSERT( 1 == 1 );
    Vector<int> aArray;
    CPPUNIT_ASSERT(aArray.size() == 0);
    aArray.push_back(2);
    CPPUNIT_ASSERT(aArray.size() == 1);
    CPPUNIT_ASSERT(aArray.back() == 2);
    CPPUNIT_ASSERT(aArray.size() == 1);
}
