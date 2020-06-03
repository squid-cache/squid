/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_CFG_EXCEPTIONS_H
#define SQUID__SRC_CFG_EXCEPTIONS_H

#include "sbuf/Stream.h"

#include <limits>
#include <stdexcept>

namespace Cfg
{

/**
 * Helper class to distinguish serious parsing errors which need
 * Administrative attention before Squid can operate.
 */
class FatalError : public std::exception
{
public:
    /// NP: use ToSBuf(...) if the error message is complex
    explicit FatalError(const SBuf &m) :
        message(m)
    {}
    explicit FatalError(const char *m) :
        message(m)
    {}

    /* std::exception API */
    const char *what() const throw() override;

public:
    /// the error message text to display
    SBuf message;
};

// Gadgets to throw consistent error messages on common squid.conf requirements.

/// throws a Cfg::FatalError if value is unset
void RequireValue(const char *key, const char *value);

/// throws a Cfg::FatalError if value is zero or negative
template<typename T>
void
RequirePositiveValue(const char *key, const T &value)
{
    if (!std::is_unsigned<T>() && value <= 0)
        throw Cfg::FatalError(ToSBuf("option ", key, " value must be a positive number. Got: ", value));
}

/// convert a value for storage in a smaller integral type T, or to have a limited numeric range.
template<typename T>
T
DownsizeValue(const char *str, const int64_t &input, const T low = std::numeric_limits<T>::min(), const T high = std::numeric_limits<T>::max())
{
    // check this is actually a downsize, not upgrade
    static_assert(std::numeric_limits<int64_t>::min() <= std::numeric_limits<T>::min(), "std::numeric_limits<int64_t>::min() <= std::numeric_limits<T>::min()");
    static_assert(std::numeric_limits<int64_t>::max() >= std::numeric_limits<T>::max(), "std::numeric_limits<int64_t>::max() >= std::numeric_limits<T>::max()");
    static_assert(sizeof(int64_t) >= sizeof(T), "sizeof(int64_t) >= sizeof(T)");

    if (input < low)
        throw Cfg::FatalError(ToSBuf("invalid value: ", str, " must be above ", low));

    if (input > high)
        throw Cfg::FatalError(ToSBuf("invalid value: ", str, " must be below ", high));

    T result = static_cast<T>(input);
    if (input != static_cast<int64_t>(result))
        throw Cfg::FatalError(ToSBuf("invalid value: '", str, "' (", input, ") overflows when converted to '", typeid(T).name(), "'"));

    return result;
}

/// throws a Cfg::FatalError if value is outside the given range
template<typename T>
void
RequireRangedInt(const char *key, const char *value, T &result, const int low = 0, const int high = std::numeric_limits<T>::max())
{
    if (!xstrtoui(value, nullptr, &result, low, high))
        throw Cfg::FatalError(ToSBuf("invalid value for ", key, value));
}

} // namespace Cfg

#endif /* SQUID__SRC_CFG_EXCEPTIONS_H */
