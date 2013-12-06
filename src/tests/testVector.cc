#define SQUID_UNIT_TEST 1
#include "squid.h"
#include "base/Vector.h"
#include "tests/testVector.h"

#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( testVector );

void testVector::all()
{
    CPPUNIT_ASSERT_EQUAL(1 ,  1);
    Vector<int> aArray;
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(0), aArray.size());
    aArray.push_back(2);
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), aArray.size());
    CPPUNIT_ASSERT_EQUAL(2, aArray.back());
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), aArray.size());
}
