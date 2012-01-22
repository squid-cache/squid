#define SQUID_UNIT_TEST 1
#include "squid.h"

#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "testArray.h"
#include "Array.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testArray );

void testArray::all()
{
    CPPUNIT_ASSERT( 1 == 1 );
    Vector<int> aArray;
    CPPUNIT_ASSERT (aArray.size() == 0);
    aArray.push_back(2);
    CPPUNIT_ASSERT (aArray.size() == 1);
    CPPUNIT_ASSERT (aArray.back() == 2);
    CPPUNIT_ASSERT (aArray.size() == 1);
}
