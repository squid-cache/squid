/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_IOMANIP_H
#define SQUID_SRC_BASE_IOMANIP_H

#include "debug/Stream.h"

#include <iostream>
#include <iomanip>
#include <optional>

/// \section Custom manipulator tuning methods
///
/// Our convenience manipulator/wrapper classes often have methods that tune
/// their "printing" effects (e.g., AsHex::minDigits()). STL streams also have
/// manipulators that tune how subsequent operator "<<" parameters are printed
/// (e.g., std::setw()). The calling code can also print various decorations
/// (i.e. prefixes and suffixes). The following principles are useful when
/// deciding what manipulator methods to add and how to implement them:
///
/// \li Add a manipulator method if callers would otherwise have to restore
/// stream format after calling the manipulator. For example, AsHex::toUpper()
/// frees callers from doing `std::uppercase << asHex(n) << std::nouppercase`.
///
/// \li Add a manipulator method if callers would otherwise have to use
/// conditionals to get the same effect. For example, AsList::prefixedBy() frees
/// callers from doing `(c.empty() ? "" : "/") << asList(c)`.
///
/// \li Add a manipulator method if callers would otherwise have to repeat a
/// combination of actions to get the right effect. For example,
/// AsList::minDigits() prevents duplication of the following caller code:
/// `std::setfill('0') << std::setw(8) << asHex(n)`.
///
/// \li Avoid adding a manipulator method that can be _fully_ replaced with a
/// _single_ caller item. For example, do not add AsX::foo() if callers can do
/// `bar << asX(y)` or `asX(y) << bar` and get exactly the same effect.
///
/// \li Manipulators should honor existing stream formatting to the extent
/// possible (e.g., AsHex honors std::uppercase by default).

/// Safely prints an object pointed to by the given pointer: [label]<object>
/// Prints nothing at all if the pointer is nil.
template <class Pointer>
class RawPointerT {
public:
    RawPointerT(const char *aLabel, const Pointer &aPtr):
        label(aLabel), ptr(aPtr) {}

    /// Report the pointed-to-object on a dedicated Debug::Extra line.
    RawPointerT<Pointer> &asExtra() { onExtraLine = true; return *this; }

    /// enable and, optionally, customize reporting of nil pointers
    RawPointerT<Pointer> &orNil(const char *nilTextToUse = "[nil]") { nilText = nilTextToUse; return *this; }

    const char *label; /// the name or description of the being-debugged object

    /// whether and how to report a nil pointer; use orNil() to enable
    const char *nilText = nullptr;

    const Pointer &ptr; /// a possibly nil pointer to the being-debugged object
    bool onExtraLine = false;
};

/// convenience wrapper for creating RawPointerT<> objects
template <class Pointer>
inline RawPointerT<Pointer>
RawPointer(const char *label, const Pointer &ptr)
{
    return RawPointerT<Pointer>(label, ptr);
}

/// convenience wrapper for creating RawPointerT<> objects without a label
template <class Pointer>
inline RawPointerT<Pointer>
RawPointer(const Pointer &ptr)
{
    return RawPointerT<Pointer>(nullptr, ptr);
}

/// prints RawPointerT<>, dereferencing the io_manip pointer if possible
template <class Pointer>
inline std::ostream &
operator <<(std::ostream &os, const RawPointerT<Pointer> &pd)
{
    if (!pd.ptr) {
        if (pd.nilText)
            os << pd.nilText;
        return os;
    }

    if (pd.onExtraLine)
        os << Debug::Extra;

    if (pd.label)
        os << pd.label;

    os << *pd.ptr;

    return os;
}

/// std::ostream manipulator to print integers and alike as hex numbers.
/// Normally used through the asHex() convenience function.
template <class Integer>
class AsHex
{
public:
    // Without this assertion, asHex(pointer) and AsHex(3.14) compile, but their
    // caller is likely confused about the actual argument type and expects
    // different output. Enum values are not integral types but arguably do not
    // cause similar problems.
    static_assert(std::is_integral<Integer>::value || std::is_enum<Integer>::value);

    explicit AsHex(const Integer n): io_manip(n) {}

    /// Sets the minimum number of digits to print. If the integer has fewer
    /// digits than the given width, then we also print leading zero(s).
    /// Otherwise, this method has no effect.
    auto &minDigits(const size_t w) { forcePadding = w; return *this; }

    /// Print hex digits in upper (or, with a false parameter value, lower) case.
    auto &upperCase(const bool u = true) { forceCase = u; return *this; }

    Integer io_manip; ///< the integer to print

    /// \copydoc minDigits()
    /// The default is to use stream's field width and stream's fill character.
    std::optional<size_t> forcePadding;

    /// \copydoc upperCase()
    /// The default is to use stream's std::uppercase flag.
    std::optional<bool> forceCase;
};

template <class Integer>
inline std::ostream &
operator <<(std::ostream &os, const AsHex<Integer> number)
{
    const auto oldFlags = os.flags();
    const auto oldFill = os.fill();

    if (number.forceCase)
        os << (*number.forceCase ? std::uppercase : std::nouppercase);

    if (number.forcePadding) {
        os.width(*number.forcePadding);
        os.fill('0');
    }

    // When Integer is smaller than int, the unary plus converts the stored
    // value into an equivalent integer because C++ "arithmetic operators do not
    // accept types smaller than int as arguments, and integral promotions are
    // automatically applied". For larger integer types, plus is a no-op.
    os << std::hex << +number.io_manip;

    os.fill(oldFill);
    os.flags(oldFlags);
    return os;
}

/// a helper to ease AsHex object creation
template <class Integer>
inline AsHex<Integer> asHex(const Integer n) { return AsHex<Integer>(n); }

/// Prints the first n data bytes using hex notation. Does nothing if n is 0.
void PrintHex(std::ostream &, const char *data, size_t n);

/// std::ostream manipulator to print containers as flat lists
template <typename Container>
class AsList
{
public:
    explicit AsList(const Container &c): container(c) {}

    /// a c-string to print before the first item (if any). Caller must ensure lifetime.
    auto &prefixedBy(const char * const p) { prefix = p; return *this; }

    /// a c-string to print after the last item (if any). Caller must ensure lifetime.
    auto &suffixedBy(const char * const p) { suffix = p; return *this; }

    /// a c-string to print between consecutive items (if any). Caller must ensure lifetime.
    auto &delimitedBy(const char * const d) { delimiter = d; return *this; }

    /// c-string to print before and after each item. Caller must ensure lifetime.
    auto &quoted(const char * const q = "\"") { preQuote = postQuote = q; return *this; }

    /// c-strings to print before and after each item. Caller must ensure lifetime.
    auto &quoted(const char * const preQ, const char * const postQ) { preQuote = preQ; postQuote = postQ; return *this; }

    /// writes the container to the given stream
    void print(std::ostream &) const;

public:
    const Container &container; ///< zero or more items to print

    const char *prefix = nullptr; ///< \copydoc prefixedBy()
    const char *suffix = nullptr; ///< \copydoc suffixedBy()
    const char *delimiter = nullptr; ///< \copydoc delimitedBy()
    const char *preQuote = nullptr; ///< optional c-string to print before each item; \sa quoted()
    const char *postQuote = nullptr; ///< optional c-string to print after each item; \sa quoted()
};

template <typename Container>
void
AsList<Container>::print(std::ostream &os) const
{
    bool opened = false;

    for (const auto &item: container) {
        if (!opened) {
            if (prefix)
                os << prefix;
            opened = true;
        } else {
            if (delimiter)
                os << delimiter;
        }

        if (preQuote)
            os << preQuote;
        os << item;
        if (postQuote)
            os << postQuote;
    }

    if (opened && suffix)
        os << suffix;
}

template <typename Container>
inline std::ostream &
operator <<(std::ostream &os, const AsList<Container> &manipulator)
{
    manipulator.print(os);
    return os;
}

/// a helper to ease AsList object creation
template <typename Container>
inline auto asList(const Container &c) { return AsList<Container>(c); }

/// Helps print T object at most once per AtMostOnce<T> object lifetime.
/// T objects are printed to std::ostream using operator "<<".
///
/// \code
/// auto headerOnce = AtMostOnce("Transaction Details:\n");
/// if (detailOne)
///     os << headerOnce << *detailOne;
/// if (const auto detailTwo = findAnotherDetail())
///     os << headerOnce << *detailTwo;
/// \endcode
template <class T>
class AtMostOnce
{
public:
    /// caller must ensure `t` lifetime extends to the last use of this AtMostOnce instance
    explicit AtMostOnce(const T &t): toPrint(t) {}

    void print(std::ostream &os) {
        if (!printed) {
            os << toPrint;
            printed = true;
        }
    }

private:
    const T &toPrint;
    bool printed = false;
};

/// Prints AtMostOnce argument if needed. The argument is not constant to
/// prevent wrong usage:
///
/// \code
/// /* Compiler error: cannot bind non-const lvalue reference to an rvalue */
/// os << AtMostOnce(x);
/// \endcode
template <class T>
inline auto &
operator <<(std::ostream &os, AtMostOnce<T> &a) {
    a.print(os);
    return os;
}

#endif /* SQUID_SRC_BASE_IOMANIP_H */

