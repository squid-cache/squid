/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SQUIDMATH_H
#define SQUID_SRC_SQUIDMATH_H

#include "base/forward.h"
#include "base/TypeTraits.h"

#include <limits>
#include <optional>

// TODO: Move to src/base/Math.h and drop the Math namespace

/* Math functions we define locally for Squid */
namespace Math
{

int intPercent(const int a, const int b);
int64_t int64Percent(const int64_t a, const int64_t b);
double doublePercent(const double, const double);
int intAverage(const int, const int, int, const int);
double doubleAverage(const double, const double, int, const int);

} // namespace Math

// If Sum() performance becomes important, consider using GCC and clang
// built-ins like __builtin_add_overflow() instead of manual overflow checks.

/// detects a pair of unsigned types
/// reduces code duplication in declarations further below
template <typename T, typename U>
using AllUnsigned = typename std::conditional<
                    std::is_unsigned<T>::value && std::is_unsigned<U>::value,
                    std::true_type,
                    std::false_type
                    >::type;

// TODO: Replace with std::cmp_less() after migrating to C++20.
/// whether integer a is less than integer b, with correct overflow handling
template <typename A, typename B>
constexpr bool
Less(const A a, const B b) {
    // The casts below make standard C++ integer conversions explicit. They
    // quell compiler warnings about signed/unsigned comparison. The first two
    // lines exclude different-sign a and b, making the casts/comparison safe.
    using AB = typename std::common_type<A, B>::type;
    return
        (a >= 0 && b < 0) ? false :
        (a < 0 && b >= 0) ? true :
        /* (a >= 0) == (b >= 0) */ static_cast<AB>(a) < static_cast<AB>(b);
}

/// ensure that T is supported by NaturalSum() and friends
template<typename T>
constexpr void
AssertNaturalType()
{
    static_assert(std::numeric_limits<T>::is_bounded, "std::numeric_limits<T>::max() is meaningful");
    static_assert(std::numeric_limits<T>::is_exact, "no silent loss of precision");
    static_assert(!std::is_enum<T>::value, "no silent creation of non-enumerated values");
}

// TODO: Investigate whether this optimization can be expanded to [signed] types
// A and B when std::numeric_limits<decltype(A(0)+B(0))>::is_modulo is true.
/// This IncreaseSumInternal() overload is optimized for speed.
/// \returns a non-overflowing sum of the two unsigned arguments (or nothing)
/// \prec both argument types are unsigned
template <typename S, typename A, typename B, std::enable_if_t<AllUnsigned<A,B>::value, int> = 0>
std::optional<S>
IncreaseSumInternal(const A a, const B b) {
    // paranoid: AllUnsigned<A,B> precondition established that already
    static_assert(std::is_unsigned<A>::value, "AllUnsigned dispatch worked for A");
    static_assert(std::is_unsigned<B>::value, "AllUnsigned dispatch worked for B");

    AssertNaturalType<S>();
    AssertNaturalType<A>();
    AssertNaturalType<B>();

    // we should only be called by IncreaseSum(); it forces integer promotion
    static_assert(std::is_same<A, decltype(+a)>::value, "a will not be promoted");
    static_assert(std::is_same<B, decltype(+b)>::value, "b will not be promoted");
    // and without integer promotions, a sum of unsigned integers is unsigned
    static_assert(std::is_unsigned<decltype(a+b)>::value, "a+b is unsigned");

    // with integer promotions ruled out, a or b can only undergo integer
    // conversion to the higher rank type (A or B, we do not know which)
    using AB = typename std::common_type<A, B>::type;
    static_assert(std::is_same<AB, A>::value || std::is_same<AB, B>::value, "no unexpected conversions");
    static_assert(std::is_same<AB, decltype(a+b)>::value, "lossless assignment");
    const AB sum = a + b;

    static_assert(std::numeric_limits<AB>::is_modulo, "we can detect overflows");
    // 1. modulo math: overflowed sum is smaller than any of its operands
    // 2. the sum may overflow S (i.e. the return base type)
    // We do not need Less() here because we compare promoted unsigned types.
    return (sum >= a && sum <= std::numeric_limits<S>::max()) ?
           std::optional<S>(sum) : std::optional<S>();
}

/// This IncreaseSumInternal() overload supports a larger variety of types.
/// \returns a non-overflowing sum of the two arguments (or nothing)
/// \returns nothing if at least one of the arguments is negative
/// \prec at least one of the argument types is signed
template <typename S, typename A, typename B, std::enable_if_t<!AllUnsigned<A,B>::value, int> = 0>
std::optional<S> constexpr
IncreaseSumInternal(const A a, const B b) {
    AssertNaturalType<S>();
    AssertNaturalType<A>();
    AssertNaturalType<B>();

    // we should only be called by IncreaseSum() that does integer promotion
    static_assert(std::is_same<A, decltype(+a)>::value, "a will not be promoted");
    static_assert(std::is_same<B, decltype(+b)>::value, "b will not be promoted");

    return
        // We could support a non-under/overflowing sum of negative numbers, but
        // our callers use negative values specially (e.g., for do-not-use or
        // do-not-limit settings) and are not supposed to do math with them.
        (a < 0 || b < 0) ? std::optional<S>() :
        // To avoid undefined behavior of signed overflow, we must not compute
        // the raw a+b sum if it may overflow. When A is not B, a or b undergoes
        // (safe for non-negatives) integer conversion in these expressions, so
        // we do not know the resulting a+b type AB and its maximum. We must
        // also detect subsequent casting-to-S overflows.
        // Overflow condition: (a + b > maxAB) or (a + b > maxS).
        // A is an integer promotion of S, so maxS <= maxA <= maxAB.
        // Since maxS <= maxAB, it is sufficient to just check: a + b > maxS,
        // which is the same as the overflow-safe condition here: maxS - a < b.
        // Finally, (maxS - a) cannot overflow because a is not negative and
        // cannot underflow because a is a promotion of s: 0 <= a <= maxS.
        Less(std::numeric_limits<S>::max() - a, b) ? std::optional<S>() :
        std::optional<S>(a + b);
}

/// argument pack expansion termination for IncreaseSum<S, T, Args...>()
template <typename S, typename T>
std::optional<S>
IncreaseSum(const S s, const T t)
{
    // Force (always safe) integer promotions now, to give std::enable_if_t<>
    // promoted types instead of entering IncreaseSumInternal<AllUnsigned>(s,t)
    // but getting a _signed_ promoted value of s or t in s + t.
    return IncreaseSumInternal<S>(+s, +t);
}

/// \returns a non-overflowing sum of the arguments (or nothing)
template <typename S, typename T, typename... Args>
std::optional<S>
IncreaseSum(const S sum, const T t, const Args... args) {
    if (const auto head = IncreaseSum(sum, t)) {
        return IncreaseSum(head.value(), args...);
    } else {
        // std::optional<S>() triggers bogus -Wmaybe-uninitialized warnings in GCC v10.3
        return std::nullopt;
    }
}

/// \returns an exact, non-overflowing sum of the arguments (or nothing)
template <typename SummationType, typename... Args>
std::optional<SummationType>
NaturalSum(const Args... args) {
    return IncreaseSum<SummationType>(0, args...);
}

/// Safely resets the given variable to NaturalSum() of the given arguments.
/// If the sum overflows, resets to variable's maximum possible value.
/// \returns the new variable value (like an assignment operator would)
template <typename S, typename... Args>
S
SetToNaturalSumOrMax(S &var, const Args... args)
{
    var = NaturalSum<S>(args...).value_or(std::numeric_limits<S>::max());
    return var;
}

/// converts a given non-negative integer into an integer of a given type
/// without loss of information or undefined behavior
template <typename Result, typename Source>
Result
NaturalCast(const Source s)
{
    return NaturalSum<Result>(s).value();
}

#endif /* SQUID_SRC_SQUIDMATH_H */

