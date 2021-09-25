/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_SQUIDMATH_H
#define _SQUID_SRC_SQUIDMATH_H

#include "base/forward.h"

#include <limits>
#include <type_traits>

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

/// std::enable_if_t replacement until C++14
/// simplifies Sum() declarations below
template <bool B, class T = void>
using EnableIfType = typename std::enable_if<B,T>::type;

/// detects a pair of unsigned types
/// reduces code duplication in Sum() declarations below
template <typename A, typename B>
using AllUnsigned = typename std::conditional<
                    std::is_unsigned<A>::value && std::is_unsigned<B>::value,
                    std::true_type,
                    std::false_type
                    >::type;

/// whether integer a is less than integer b, with correct overflow handling
template <typename A, typename B>
constexpr bool
Less(const A a, const B b) {
    // The casts below make standard C++ integral conversions explicit. They
    // quell compiler warnings about signed/unsigned comparison. The first two
    // lines exclude different-sign a and b, making the casts/comparison safe.
    using AB = typename std::common_type<A, B>::type;
    return
        (a >= 0 && b < 0) ? false :
        (a < 0 && b >= 0) ? true :
        /* (a >= 0) == (b >= 0) */ static_cast<AB>(a) < static_cast<AB>(b);
}

/// \returns a non-overflowing sum of the two unsigned arguments (or nothing)
template <typename S, typename T, EnableIfType<AllUnsigned<S,T>::value, int> = 0>
Optional<S>
IncreaseSum(const S s, const T t) {
    // this optimized implementation relies on unsigned overflows
    static_assert(std::is_unsigned<S>::value, "the first argument is unsigned");
    static_assert(std::is_unsigned<T>::value, "the second argument is unsigned");
    // For the sum overflow check below to work, we cannot restrict the sum
    // type which, due to integral promotions, may exceed common_type<S,T>!
    const auto sum = s + t;
    // 1. when summation overflows, the result becomes smaller than any operand
    // 2. the unknown (see above) "auto" type may hold more than S can hold
    return (s <= sum && sum <= std::numeric_limits<S>::max()) ?
           Optional<S>(sum) : Optional<S>();
}

/// \returns a non-overflowing sum of the two arguments (or nothing)
/// \returns nothing if at least one of the arguments is negative
/// at least one of the arguments is signed
template <typename S, typename T, EnableIfType<!AllUnsigned<S,T>::value, int> = 0>
Optional<S> constexpr
IncreaseSum(const S s, const T t) {
    return
        // We could support a non-under/overflowing sum of negative numbers, but
        // our callers use negative values specially (e.g., for do-not-use or
        // do-not-limit settings) and are not supposed to do math with them.
        (Less(s, 0) || Less(t, 0)) ? Optional<S>() :
        // Avoids undefined behavior of signed under/overflows. When S is not T,
        // s or t undergoes (safe) integral conversion in these expressions.
        // Sum overflow condition: s + t > maxS or, here, maxS - s < t.
        // If the sum exceeds maxT, integral conversions will use S, not T.
        Less(std::numeric_limits<S>::max() - s, t) ? Optional<S>() :
        Optional<S>(s + t);
}

/// \returns a non-overflowing sum of the arguments (or nothing)
template <typename S, typename T, typename... Args>
Optional<S>
IncreaseSum(const S sum, const T t, Args... args) {
    if (const auto head = IncreaseSum<S>(sum, t)) {
        return IncreaseSum<S>(head.value(), args...);
    } else {
        return Optional<S>();
    }
}

/// \returns an exact, non-overflowing sum of the arguments (or nothing)
template <typename SummationType, typename... Args>
Optional<SummationType>
NaturalSum(Args... args) {
    return IncreaseSum<SummationType>(0, args...);
}

/// Safely resets the given variable to NaturalSum() of the given arguments.
/// If the sum overflows, resets to variable's maximum possible value.
/// \returns the new variable value (like an assignment operator would)
template <typename S, typename... Args>
S
SetToNaturalSumOrMax(S &var, Args... args)
{
    var = NaturalSum<S>(args...).value_or(std::numeric_limits<S>::max());
    return var;
}

#endif /* _SQUID_SRC_SQUIDMATH_H */

