/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_BASE_MATH_H
#define SQUID__SRC_BASE_MATH_H

#include "base/forward.h"

/// recursion-termination for SafeSum() below
template<typename T>
Optional<T>
SafeSum(T first) {
    return Optional<T>(first);
}

/// \returns a non-overflowing sum of the arguments (or nothing)
template<typename T, typename... Args>
Optional<T>
SafeSum(T first, Args... args) {
    // the current optimized implementation may cause undefined behavior for
    // signed arguments because the effects of signed overflow are undefined
    static_assert(std::is_unsigned<T>::value, "SafeSum arguments are unsigned");

    if (const auto others = SafeSum(args...)) {
        const auto sum = first + others.value();
        // when a+b overflows, the result becomes smaller than any operand
        return (sum < first) ? Optional<T>() : Optional<T>(sum);
    } else {
        return Optional<T>();
    }
}

#endif /* SQUID__SRC_BASE_MATH_H */
