/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "tests/testEnumIterator.h"
#include "unitTestMain.h"

#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( TestEnumIterator );

enum class TestEnum {
    enumBegin_ = 0,
    zero = enumBegin_,
    one,
    two,
    three,
    four,
    enumEnd_
};

enum class UnsignedTestEnum : unsigned char {
    enumBegin_ = 0,
    zero = enumBegin_,
    one,
    two,
    three,
    four,
    enumEnd_
};

void
TestEnumIterator::testForwardIter()
{
    WholeEnum<TestEnum>::iterator i = WholeEnum<TestEnum>().begin();
    CPPUNIT_ASSERT(*i == TestEnum::zero);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::one);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::two);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::three);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::four);
    ++i;
    CPPUNIT_ASSERT(i == WholeEnum<TestEnum>().end());
}

void
TestEnumIterator::testReverseIter()
{
    WholeEnum<TestEnum>::reverse_iterator i = WholeEnum<TestEnum>().rbegin();
    CPPUNIT_ASSERT(*i == TestEnum::four);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::three);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::two);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::one);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::zero);
    ++i;
    CPPUNIT_ASSERT(i == WholeEnum<TestEnum>().rend());
}

void
TestEnumIterator::testBidirectionalIter()
{
    WholeEnum<TestEnum>::iterator i = WholeEnum<TestEnum>().begin();
    CPPUNIT_ASSERT(*i == TestEnum::zero);
    ++i;
    CPPUNIT_ASSERT(*i == TestEnum::one);
    --i;
    CPPUNIT_ASSERT(*i == TestEnum::zero);

    auto enumBegin=WholeEnum<TestEnum>().begin();
    auto enumEnd=WholeEnum<TestEnum>().end();
    i=enumBegin;
    int count=0;
    while (i != enumEnd) {
        ++i;
        ++count;
        if (count > 20) // prevent infinite loops in test
            break;
    }
    while (i != enumBegin) {
        --i;
        ++count;
        if (count > 20) // prevent infinite loops in test
            break;
    }
    CPPUNIT_ASSERT_EQUAL(10, count);

    --i; //intentional out-of-bounds
    CPPUNIT_ASSERT(i != enumBegin);
    CPPUNIT_ASSERT(*i != TestEnum::zero);
}

void
TestEnumIterator::testRangeFor()
{
    int j = 0;
    for (auto e : WholeEnum<TestEnum>()) {
        (void)e;
        ++j;
        if (j > 20) // prevent infinite loops in test
            break;
    }
    CPPUNIT_ASSERT_EQUAL(5,j);
}

void
TestEnumIterator::testRangeForRange()
{
    int j = 0;
    // free function-based range
    for (auto e : EnumRange(TestEnum::two, TestEnum::four)) {
        (void)e;
        ++j;
        if (j > 20) // prevent infinite loops in test
            break;
    }
    CPPUNIT_ASSERT_EQUAL(2,j);
}

void
TestEnumIterator::testUnsignedEnum()
{
    int j = 0;
    for (auto e = WholeEnum<TestEnum>().rbegin(); e != WholeEnum<TestEnum>().rend(); ++e ) {
        (void)e;
        ++j;
        if (j > 20) // prevent infinite loops in test
            break;
    }
    CPPUNIT_ASSERT_EQUAL(5,j);
}

