/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_TYPETRAITS_H
#define SQUID_SRC_BASE_TYPETRAITS_H

#include <type_traits>

namespace TypeTraits_ { // a hack to prevent "unintended ADL"

// TODO: Extract reusable paradigms into other mixins (e.g., NonCopyable).
/// convenience base for any class with pure virtual method(s)
class Interface
{
public:
    // ensures proper destruction via pointers to base interface classes
    virtual ~Interface() = default;

    // prohibits copy/move assignment to prevent accidental object slicing
    Interface &operator=(const Interface &) = delete;
    Interface &operator=(Interface &&) = delete;

protected: // prevents accidental creation of Interface instances

    // allows default-construction in kids
    constexpr Interface() = default;

    // allows copy/move construction for kids convenience
    Interface(const Interface &) = default;
    Interface(Interface &&) = default;
};

/// convenience base for any class to prohibit default move and copy
class NonCopyable
{
protected:
    NonCopyable() = default;
    NonCopyable(NonCopyable &&) = delete;
};

} // namespace TypeTraits_

using Interface = TypeTraits_::Interface;
using NonCopyable = TypeTraits_::NonCopyable;

#endif /* SQUID_SRC_BASE_TYPETRAITS_H */

