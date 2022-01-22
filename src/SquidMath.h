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
#include "base/Optional.h"

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

// If IncreaseSumInternal() speed becomes important, consider using compiler
// built-ins like __builtin_add_overflow() instead of manual overflow checks.

/// std::enable_if_t replacement until C++14
/// simplifies IncreaseSumInternal() declarations below
template <bool B, class T = void>
using EnableIfType = typename std::enable_if<B,T>::type;

/// detects a pair of unsigned types
/// reduces code duplication in IncreaseSumInternal() declarations below
template <typename A, typename B>
using AllUnsigned = typename std::conditional<
                    std::is_unsigned<A>::value && std::is_unsigned<B>::value,
                    std::true_type,
                    std::false_type
                    >::type;

// TODO: Replace with std::cmp_less() after migrating to C++20.
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

/// ensure that T is supported by NaturalSum() and friends
template<typename T>
constexpr bool
AssertNaturalType()
{
    static_assert(std::numeric_limits<T>::is_bounded, "std::numeric_limits<T>::max() is meaningful");
    static_assert(std::numeric_limits<T>::is_exact, "no silent loss of precision");
    static_assert(!std::is_enum<T>::value, "no silent creation of non-enumerated values");
    return true; // for static_assert convenience in C++11 constexpr callers
}

// TODO: Investigate whether this optimization can be expanded to [signed] types
// S and T when std::numeric_limits<decltype(S(0)+T(0))>::is_modulo is true.
/// This IncreaseSumInternal() overload is optimized for speed.
/// \returns a non-overflowing sum of the two unsigned arguments (or nothing)
/// \prec both argument types are unsigned
template <typename S, typename T, EnableIfType<AllUnsigned<S,T>::value, int> = 0>
Optional<S>
IncreaseSumInternal(const S s, const T t) {
    // TODO: Just call AssertNaturalType() after upgrading to C++14.
    static_assert(AssertNaturalType<S>(), "S is a supported type");
    static_assert(AssertNaturalType<T>(), "T is a supported type");

    // For the sum overflow check below to work, we cannot restrict the sum
    // type which, due to integral promotions, may exceed common_type<S,T>!
    const auto sum = s + t;
    static_assert(std::numeric_limits<decltype(sum)>::is_modulo, "we can detect overflows");
    // 1. modulo math: overflowed sum is smaller than any of its operands
    // 2. the unknown (see above) "auto" type may hold more than S can hold
    return (s <= sum && sum <= std::numeric_limits<S>::max()) ?
           Optional<S>(sum) : Optional<S>();
}

/// This IncreaseSumInternal() overload supports a larger variety of types.
/// \returns a non-overflowing sum of the two arguments (or nothing)
/// \returns nothing if at least one of the arguments is negative
/// \prec at least one of the argument types is signed
template <typename S, typename T, EnableIfType<!AllUnsigned<S,T>::value, int> = 0>
Optional<S> constexpr
IncreaseSumInternal(const S s, const T t) {
    static_assert(AssertNaturalType<S>(), "S is a supported type");
    static_assert(AssertNaturalType<T>(), "T is a supported type");
    return
        // We could support a non-under/overflowing sum of negative numbers, but
        // our callers use negative values specially (e.g., for do-not-use or
        // do-not-limit settings) and are not supposed to do math with them.
        (s < 0 || t < 0) ? Optional<S>() :
        // To avoid undefined behavior of signed overflow, we must not compute
        // the raw s+t sum if it may overflow. When S is not T, s or t undergoes
        // (safe for non-negatives) integral conversion in these expressions, so
        // we do not know the resulting s+t type ST and its maximum. We must
        // also detect subsequent casting-to-S overflows.
        // Overflow condition: (s + t > maxST) or (s + t > maxS).
        // Since maxS <= maxST, it is sufficient to just check: s + t > maxS,
        // which is the same as the overflow-safe condition here: maxS - s < t.
        Less(std::numeric_limits<S>::max() - s, t) ? Optional<S>() :
        Optional<S>(s + t);
}

/// argument pack expansion termination for IncreaseSum<S, T, Args...>()
template <typename S, typename T>
Optional<S>
IncreaseSum(const S s, const T t)
{
    // Force (always safe) integral promotions now, to give EnableIfType<>
    // promoted types instead of entering IncreaseSumInternal<AllUnsigned>(s,t)
    // but getting a _signed_ promoted value of s or t in s + t.
    return IncreaseSumInternal<S>(+s, +t);
}

/// \returns a non-overflowing sum of the arguments (or nothing)
template <typename S, typename T, typename... Args>
Optional<S>
IncreaseSum(const S sum, const T t, const Args... args) {
    if (const auto head = IncreaseSum(sum, t)) {
        return IncreaseSum(head.value(), args...);
    } else {
        return Optional<S>();
    }
}

/// \returns an exact, non-overflowing sum of the arguments (or nothing)
template <typename SummationType, typename... Args>
Optional<SummationType>
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

#endif /* _SQUID_SRC_SQUIDMATH_H */

