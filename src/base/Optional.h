/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_BASE_OPTIONAL_H
#define SQUID__SRC_BASE_OPTIONAL_H

#include <exception>
#include <type_traits>
#include <utility>

/// std::bad_optional_access replacement (until we upgrade to C++17)
class BadOptionalAccess: public std::exception
{
public:
    BadOptionalAccess() {}
    /* std::exception API */
    virtual const char* what() const noexcept override { return "bad-optional-access"; }
    virtual ~BadOptionalAccess() noexcept = default;
};

/// (limited) std::optional replacement (until we upgrade to C++17)
template <typename Value>
class Optional
{
public:
    constexpr Optional() noexcept: dummy_() {}
    constexpr explicit Optional(const Value &v): value_(v), hasValue_(true) {}

    ~Optional()
    {
        // XXX: This simplified implementation does not keep the destructor
        // trivial for trivial Value types, but optimizing compilers still
        // optimize such destruction away, and that is sufficient for our
        // current needs.
        reset();
    }

    constexpr Optional(const Optional &other): Optional()
    {
        if (other.hasValue_)
            *this = other.value_;
    }

    Optional &operator =(const Optional &other)
    {
        if (this != &other) {
            if (other.hasValue_)
                *this = other.value_;
            else
                reset();
        }
        return *this;
    }

    Optional(Optional<Value> &&other): Optional()
    {
        if (other.hasValue_) {
            *this = std::move(other.value_);
            // no other.reset() per std::optional move semantics
        }
    }

    Optional &operator =(Optional<Value> &&other)
    {
        if (this != &other) {
            if (other.hasValue_) {
                *this = std::move(other.value_);
                // no other.reset() per std::optional move semantics
            } else {
                reset();
            }
        }
        return *this;
    }

    constexpr explicit operator bool() const noexcept { return hasValue_; }
    constexpr bool has_value() const noexcept { return hasValue_; }

    const Value &value() const &
    {
        if (!hasValue_)
            throw BadOptionalAccess();
        return value_;
    }

    template <class Other>
    constexpr Value value_or(Other &&defaultValue) const &
    {
        return hasValue_ ? value_ : static_cast<Value>(std::forward<Other>(defaultValue));
    }

    template <class Other = Value>
    Optional &operator =(Other &&otherValue)
    {
        value_ = std::forward<Other>(otherValue);
        hasValue_ = true;
        return *this;
    }

    void reset() {
        if (hasValue_) {
            hasValue_ = false;
            value_.~Value();
        }
    }

private:
    union {
        /// unused member that helps satisfy various C++ union requirements
        struct {} dummy_;

        /// stored value; inaccessible/uninitialized unless hasValue_
        Value value_;
    };

    bool hasValue_ = false;
};

#endif /* SQUID__SRC_BASE_OPTIONAL_H */

