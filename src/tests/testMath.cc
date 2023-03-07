/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "SquidMath.h"
#include "unitTestMain.h"

class TestMath: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( TestMath );
    CPPUNIT_TEST( testNaturalSum );
    CPPUNIT_TEST_SUITE_END();

protected:
    void testNaturalSum();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestMath );

/// bit-width-specific integers, for developer convenience and code readability
/// @{
static const auto min64s = std::numeric_limits<int64_t>::min();
static const auto min8s = std::numeric_limits<int8_t>::min();
static const auto zero8s = int8_t(0);
static const auto zero8u = uint8_t(0);
static const auto zero64s = int64_t(0);
static const auto zero64u = uint64_t(0);
static const auto one8s = int8_t(1);
static const auto one8u = uint8_t(1);
static const auto one64s = int64_t(1);
static const auto one64u = uint64_t(1);
static const auto max8s = std::numeric_limits<int8_t>::max();
static const auto max8u = std::numeric_limits<uint8_t>::max();
static const auto max64s = std::numeric_limits<int64_t>::max();
static const auto max64u = std::numeric_limits<uint64_t>::max();
/// @}

/// helper functions to convert NaturalSum<S>(a,b,...) calls to strings
/// @{

template <typename A>
static std::string
TypeToString()
{
    const std::string prefix = std::is_signed<A>::value ? "" : "u";
    return prefix + "int" + std::to_string(sizeof(A)*8);
}

template <typename A>
static std::string
OperandToString(const A a)
{
    return TypeToString<A>() + '(' + std::to_string(+a) + ')';
}

template <typename S, typename A, typename B>
static std::string
SumToString(const A a, const B b)
{
    return TypeToString<S>() + ": " + OperandToString(a) + " + " + OperandToString(b);
}

template <typename S, typename A, typename B, typename C>
static std::string
SumToString(const A a, const B b, const C c)
{
    return TypeToString<S>() + ": " + OperandToString(a) + " + " + OperandToString(b) + " + " + OperandToString(c);
}

/// @}

/// ends argument recursion for RawSum() with parameters
template <typename S>
static S
RawSum()
{
    return S(0);
}

/// helper function to add up an arbitrary number of arbitrary-type integers
/// while converting every number to type S and ignoring any under/overflows
template <typename S, typename A, typename... Args>
static S
RawSum(A a, Args... args)
{
    return S(a) + RawSum<S>(args...);
}

/// Tests NaturalSum<S>() calls that are supposed to succeed.
/// Implemented as a class to pass it as a template template parameter.
template <typename S>
class SuccessSumTester
{
public:
    template <typename... Args>
    static S Test(Args... args)
    {
        // to show every non-overflowing sum to be tested:
        //std::cout << SumToString<S>(args...) << " = " << +sum << "\n";

        const auto ns = NaturalSum<S>(args...);
        CPPUNIT_ASSERT_MESSAGE(SumToString<S>(args...) + " does not overflow",
                               ns.has_value());

        const auto sum = ns.value();
        const auto expected = RawSum<S>(args...);
        CPPUNIT_ASSERT_MESSAGE(
            SumToString<S>(args...) + " = " + OperandToString(expected) + " rather than " + OperandToString(sum),
            sum == expected);

        return sum;
    }
};

/// Tests NaturalSum<S>() calls that are supposed to overflow.
/// Implemented as a class to pass it as a template template parameter.
template <typename S>
class OverflowSumTester
{
public:
    template <typename... Args>
    static void Test(Args... args)
    {
        // to show every overflowing sum to be tested:
        //std::cout << SumToString<S>(args...) << " = overflow\n";

        CPPUNIT_ASSERT_MESSAGE(SumToString<S>(args...) + " must overflow",
                               !NaturalSum<S>(args...).has_value());
    }
};

/// checks that the summation outcome is unaffected by (not) adding zeros
template <typename S, template<typename> class Tester, typename A, typename B>
static void
TestWithZeros(const A a, const B b)
{
    Tester<S>::Test(a, b);

    Tester<S>::Test(zero8u, a, b);
    Tester<S>::Test(zero8s, a, b);
    Tester<S>::Test(zero64u, a, b);
    Tester<S>::Test(zero64s, a, b);
    Tester<S>::Test(a, zero8u, b);
    Tester<S>::Test(a, zero8s, b);
    Tester<S>::Test(a, zero64u, b);
    Tester<S>::Test(a, zero64s, b);
    Tester<S>::Test(a, b, zero8u);
    Tester<S>::Test(a, b, zero8s);
    Tester<S>::Test(a, b, zero64u);
    Tester<S>::Test(a, b, zero64s);
}

/// checks that the summation outcome is unaffected by the order of operands
template <typename S, template<typename> class Tester, typename A, typename B>
static void
TestOrder(const A a, const B b)
{
    TestWithZeros<S, Tester>(a, b);
    TestWithZeros<S, Tester>(b, a);
}

/// checks that a+b and similar sums overflow for summation types A and B
template <typename A, typename B>
static void
TestOverflowForEitherSummationType(const A a, const B b)
{
    TestOrder<A, OverflowSumTester>(a, b);
    TestOrder<B, OverflowSumTester>(a, b);
}

/// checks that a+b and similar sums succeed for summation type A but overflow
/// for summation type B
template <typename A, typename B>
static void
TestSuccessForFirstSummationType(const A a, const B b)
{
    TestOrder<A, SuccessSumTester>(a, b);
    TestOrder<B, OverflowSumTester>(a, b);
}

/// \returns successful a+b value using summation type S (which defaults to A)
template <typename A, typename... Args, typename S = A>
static S
GoodSum(const A a, Args... args)
{
    return SuccessSumTester<S>::Test(a, args...);
}

void
TestMath::testNaturalSum()
{
    /*
     * To simplify spelling out of these repetitive test cases, we let function
     * parameters determine the summation type. Regular code should not do that,
     * and our public summation APIs do not provide this dangerous shortcut.
     */

    // negative parameters are banned in any position
    TestOverflowForEitherSummationType(min64s, zero8s);
    TestOverflowForEitherSummationType(min64s, zero8u);
    TestOverflowForEitherSummationType(min64s, max64s);
    TestOverflowForEitherSummationType(min64s, max64u);
    TestOverflowForEitherSummationType(min8s, zero8s);
    TestOverflowForEitherSummationType(min8s, zero8s);
    TestOverflowForEitherSummationType(min8s, zero8u);
    TestOverflowForEitherSummationType(min8s, max64s);
    TestOverflowForEitherSummationType(min8s, max64u);
    TestOverflowForEitherSummationType(-1, -1);
    TestOverflowForEitherSummationType(-1, zero8s);
    TestOverflowForEitherSummationType(-1, zero8u);
    TestOverflowForEitherSummationType(-1, max64s);
    TestOverflowForEitherSummationType(-1, max64u);

    // these overflow regardless of which parameter determines the summation type
    TestOverflowForEitherSummationType(max8u, one8u);
    TestOverflowForEitherSummationType(max8u, one8s);
    TestOverflowForEitherSummationType(max8u, max8s);
    TestOverflowForEitherSummationType(max8s, one8s);
    TestOverflowForEitherSummationType(max64u, one8u);
    TestOverflowForEitherSummationType(max64u, one8s);
    TestOverflowForEitherSummationType(max64u, one64u);
    TestOverflowForEitherSummationType(max64u, one64s);
    TestOverflowForEitherSummationType(max64u, max64s);
    TestOverflowForEitherSummationType(max64s, one8u);
    TestOverflowForEitherSummationType(max64s, one8s);
    TestOverflowForEitherSummationType(max64s, one64s);

    // these overflow only if the second parameter determines the summation type
    TestSuccessForFirstSummationType(one8u, max8s);
    TestSuccessForFirstSummationType(one64u, max8u);
    TestSuccessForFirstSummationType(one64u, max64s);
    TestSuccessForFirstSummationType(one64s, max8u);
    TestSuccessForFirstSummationType(one64s, max8s);
    TestSuccessForFirstSummationType(max64u, zero8u);
    TestSuccessForFirstSummationType(max64u, zero8s);
    TestSuccessForFirstSummationType(max64s, zero8u);
    TestSuccessForFirstSummationType(max64s, zero8s);

    // a few sums with known values
    CPPUNIT_ASSERT_EQUAL(zero8s, GoodSum(zero8s, zero8u));
    CPPUNIT_ASSERT_EQUAL(zero64s, GoodSum(zero64s, zero64u));
    CPPUNIT_ASSERT_EQUAL(2, GoodSum(1, 1));
    CPPUNIT_ASSERT_EQUAL(uint64_t(2), GoodSum(one64u, one64s));
    CPPUNIT_ASSERT_EQUAL(6u, GoodSum(1u, 2, 3));
    CPPUNIT_ASSERT_EQUAL(max64u, GoodSum(zero64u, max64u));
    CPPUNIT_ASSERT_EQUAL(max64s, GoodSum(zero64s, max64s));
    CPPUNIT_ASSERT_EQUAL(one64u + max64s, GoodSum(one64u, max64s));
    CPPUNIT_ASSERT_EQUAL(max64u, GoodSum(max64u, zero8s));
    CPPUNIT_ASSERT_EQUAL(max64s, GoodSum(max64s, zero8s));

    // long argument lists (odd and even lengths)
    CPPUNIT_ASSERT_EQUAL(15, NaturalSum<int>(1, 2, 3, 4, 5).value());
    CPPUNIT_ASSERT_EQUAL(21, NaturalSum<int>(1, 2, 3, 4, 5, 6).value());

    // test SetToNaturalSumOrMax() when the sum is too big for the variable
    long expires = 0;
    const auto result = SetToNaturalSumOrMax(expires, max64u, zero8u);
    CPPUNIT_ASSERT_EQUAL(std::numeric_limits<long>::max(), expires);
    CPPUNIT_ASSERT_EQUAL(expires, result);
}

