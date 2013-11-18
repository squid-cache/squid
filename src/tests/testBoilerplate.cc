#define SQUID_UNIT_TEST 1

#include "squid.h"
#include "testBoilerplate.h"

#if HAVE_STDEXCEPT
#include <stdexcept>
#endif

CPPUNIT_TEST_SUITE_REGISTRATION( testBoilerplate );

void
testBoilerplate::testDemonstration()
{
    CPPUNIT_ASSERT_EQUAL(0, 0);
}
