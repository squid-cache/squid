/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "testPreCompiler.h"
#include "unitTestMain.h"

#include <cassert>

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

/**
 * Test several ways of defining pre-compiler directives.
 * Squid-3 uses #if FOO syntax for precompiler directives.
 * These tests ensure that the inputs will work as expected
 * when undefined macros are used in && conditions
 */
void
testPreCompiler::testIfDefAnd()
{
    /* Not Defined to exist at all == false - when used in a compound if */
#undef UNDEFINED_FOO
#define ONE_FOO 1

#if UNDEFINED_FOO && ONE_FOO
    bool undefinedAndTrueA = true;
#else
    bool undefinedAndTrueA = false;
#endif
#if !UNDEFINED_FOO && ONE_FOO
    bool undefinedAndFalseA = true;
#else
    bool undefinedAndFalseA = false;
#endif
    CPPUNIT_ASSERT(undefinedAndFalseA);
    CPPUNIT_ASSERT(!undefinedAndTrueA);

#if ONE_FOO && UNDEFINED_FOO
    bool undefinedAndTrueB = true;
#else
    bool undefinedAndTrueB = false;
#endif
#if ONE_FOO && !UNDEFINED_FOO
    bool undefinedAndFalseB = true;
#else
    bool undefinedAndFalseB = false;
#endif
    CPPUNIT_ASSERT(undefinedAndFalseB);
    CPPUNIT_ASSERT(!undefinedAndTrueB);
}

/**
 * Test several ways of defining pre-compiler directives.
 * Squid-3 uses #if FOO syntax for precompiler directives.
 * These tests ensure that the inputs will work as expected
 * when undefined macros are used in || conditions
 */
void
testPreCompiler::testIfDefOr()
{
    /* Not Defined to exist at all == false - when used in a compound if */
#undef UNDEFINED_FOO
#define ZERO_FOO 0

#if UNDEFINED_FOO || ZERO_FOO
    bool undefinedOrTrueA = true;
#else
    bool undefinedOrTrueA = false;
#endif
#if !UNDEFINED_FOO || ZERO_FOO
    bool undefinedOrFalseA = true;
#else
    bool undefinedOrFalseA = false;
#endif
    CPPUNIT_ASSERT(undefinedOrFalseA);
    CPPUNIT_ASSERT(!undefinedOrTrueA);

#if ZERO_FOO || UNDEFINED_FOO
    bool undefinedOrTrueB = true;
#else
    bool undefinedOrTrueB = false;
#endif
#if ZERO_FOO || !UNDEFINED_FOO
    bool undefinedOrFalseB = true;
#else
    bool undefinedOrFalseB = false;
#endif
    CPPUNIT_ASSERT(undefinedOrFalseB);
    CPPUNIT_ASSERT(!undefinedOrTrueB);

}

