/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
template <typename T, typename U>
using AllUnsigned = typename std::conditional<
                    std::is_unsigned<T>::value && std::is_unsigned<U>::value,
                    std::true_type,
                    std::false_type
                    >::type;

/// \returns a non-overflowing sum of the two unsigned arguments (or nothing)
template <typename T, typename U, EnableIfType<AllUnsigned<T,U>::value, int> = 0>
Optional<T>
Sum(const T a, const U b) {
    // Instead of computing the largest type dynamically, we simply go by T and
    // reject cases like Sum(0, ULLONG_MAX) that would overflow on return.
    // TODO: Consider using std::common_type<T, U> in the return type instead.
    static_assert(sizeof(T) >= sizeof(U), "Sum() return type can fit its (unsigned) result");

    // this optimized implementation relies on unsigned overflows
    static_assert(std::is_unsigned<T>::value, "the first Sum(a,b) argument is unsigned");
    static_assert(std::is_unsigned<U>::value, "the second Sum(a,b) argument is unsigned");
    const auto sum = a + b;
    // when a+b overflows, the result becomes smaller than any operand
    return (sum < a) ? Optional<T>() : Optional<T>(sum);
}

/// \returns a non-overflowing sum of the two signed arguments (or nothing)
template <typename T, typename U, EnableIfType<!AllUnsigned<T,U>::value, int> = 0>
Optional<T> constexpr
Sum(const T a, const U b) {
    // Instead of computing the largest type dynamically, we simply go by T and
    // reject cases like Sum(0, LLONG_MAX) that would overflow on return.
    static_assert(sizeof(T) >= sizeof(U), "Sum() return type can fit its (signed) result");

    // tests below avoid undefined behavior of signed under/overflows
    return b >= 0 ?
           ((a > std::numeric_limits<U>::max() - b) ? Optional<T>() : Optional<T>(a + b)):
           ((a < std::numeric_limits<U>::min() - b) ? Optional<T>() : Optional<T>(a + b));
}

/// \returns a non-overflowing sum of the arguments (or nothing)
template <typename T, typename... Args>
Optional<T>
Sum(const T first, Args... args) {
    if (const auto others = Sum<T>(args...)) {
        return Sum<T>(first, others.value());
    } else {
        return Optional<T>();
    }
}

#endif /* _SQUID_SRC_SQUIDMATH_H */

