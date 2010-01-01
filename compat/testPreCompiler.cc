#include "config.h"

#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "testPreCompiler.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testPreCompiler );

/**
 * Test several ways of defining pre-compiler directives.
 * Squid-3 uses #if FOO syntax for precompiler directives.
 * These tests ensure that the inputs will work as expected.
 */
void
testPreCompiler::testIfDef()
{
    /* Defined to explicit value 1 should be true */
#define ONE_FOO 1
#if ONE_FOO
    bool oneTrue = true;
#else
    bool oneTrue = false;
#endif
#if !ONE_FOO
    bool oneFalse = true;
#else
    bool oneFalse = false;
#endif
    CPPUNIT_ASSERT(oneTrue);
    CPPUNIT_ASSERT(!oneFalse);

    /* Defined to explicit value 0 should be false */
#define ZERO_FOO 0
#if ZERO_FOO
    bool zeroTrue = true;
#else
    bool zeroTrue = false;
#endif
#if !ZERO_FOO
    bool zeroFalse = true;
#else
    bool zeroFalse = false;
#endif
    CPPUNIT_ASSERT(zeroFalse);
    CPPUNIT_ASSERT(!zeroTrue);

    /* Defined to exist without a value generates pre-compiler errors when used in #if . */

    /* Not Defined to exist at all == false */
#undef UNDEFINED_FOO
#if UNDEFINED_FOO
    bool undefinedTrue = true;
#else
    bool undefinedTrue = false;
#endif
#if !UNDEFINED_FOO
    bool undefinedFalse = true;
#else
    bool undefinedFalse = false;
#endif
    CPPUNIT_ASSERT(undefinedFalse);
    CPPUNIT_ASSERT(!undefinedTrue);
}
