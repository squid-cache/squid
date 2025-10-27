/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_EXPECTED_H
#define SQUID_SRC_BASE_EXPECTED_H

#include <variant>

/// Either an expected value or an unexpected value. Mimics parts of C++23
/// std::expected<Value, Error> API to facilitate future seamless migration.
/// TODO: Migrate to std::expected after requiring C++23 support.
template <class Value, class Error>
class Expected
{
public:
    /* std::expected<Value, Error> API */
    using value_type = Value;
    using error_type = Error;
    Expected() = delete;
    template <typename ValueOrError = value_type>
    explicit Expected(ValueOrError &&ve) noexcept: storage_(std::forward<ValueOrError>(ve)) {}
    explicit operator bool() const noexcept { return std::holds_alternative<value_type>(storage_); }
    const value_type * operator->() const noexcept { return std::get_if<value_type>(&storage_); }
    const value_type &value() const { return std::get<value_type>(storage_); }
    const error_type &error() const { return std::get<error_type>(storage_); }

private:
    std::variant<value_type, error_type> storage_; ///< either expected or unexpected value
};

#endif /* SQUID_SRC_BASE_EXPECTED_H */

