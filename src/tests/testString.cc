/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "mem/forward.h"
#include "SquidString.h"
#include "unitTestMain.h"

/*
 * test the store framework
 */

class TestString : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestString);
    CPPUNIT_TEST(testCmpDefault);
    CPPUNIT_TEST(testCmpEmptyString);
    CPPUNIT_TEST(testCmpNotEmptyDefault);
    CPPUNIT_TEST(testSubstr);

    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    void testCmpDefault();
    void testCmpEmptyString();
    void testCmpNotEmptyDefault();
    void testSubstr();
};
CPPUNIT_TEST_SUITE_REGISTRATION(TestString);

/* init memory pools */

void
TestString::setUp()
{
    Mem::Init();
}

void
TestString::testCmpDefault()
{
    String left, right;
    /* two default strings are equal */
    CPPUNIT_ASSERT(!left.cmp(right));
    CPPUNIT_ASSERT(!left.cmp(nullptr));
    CPPUNIT_ASSERT(!left.cmp(nullptr, 1));
}

void
TestString::testCmpEmptyString()
{
    String left("");
    String right;
    /* an empty string ("") is equal to a default string */
    CPPUNIT_ASSERT(!left.cmp(right));
    CPPUNIT_ASSERT(!left.cmp(nullptr));
    CPPUNIT_ASSERT(!left.cmp(nullptr, 1));
    /* reverse the order to catch corners */
    CPPUNIT_ASSERT(!right.cmp(left));
    CPPUNIT_ASSERT(!right.cmp(""));
    CPPUNIT_ASSERT(!right.cmp("", 1));
}

void
TestString::testCmpNotEmptyDefault()
{
    String left("foo");
    String right;
    /* empty string sorts before everything */
    CPPUNIT_ASSERT(left.cmp(right) > 0);
    CPPUNIT_ASSERT(left.cmp(nullptr) > 0);
    CPPUNIT_ASSERT(left.cmp(nullptr, 1) > 0);
    /* reverse for symmetry tests */
    CPPUNIT_ASSERT(right.cmp(left) < 0);
    CPPUNIT_ASSERT(right.cmp("foo") < 0);
    CPPUNIT_ASSERT(right.cmp("foo", 1) < 0);
}

void TestString::testSubstr()
{
    String s("0123456789");
    String check=s.substr(3,5);
    String ref("34");
    CPPUNIT_ASSERT(check == ref);
}

