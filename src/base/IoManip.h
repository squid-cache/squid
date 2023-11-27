/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_IO_MANIP_H
#define SQUID_SRC_BASE_IO_MANIP_H

#include "debug/Stream.h"

#include <iostream>
#include <iomanip>

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

/// std::ostream manipulator to print integers as hex numbers prefixed by 0x
/// Normally used through the asHex() convenience function
template <class Integer>
class AsHex
{
public:
    explicit AsHex(const Integer n) : io_manip(n) {}
    auto &minDigits(const size_t w) { width = w; return *this; }
    auto &upperCase(bool u = true) { upperCase_ = u; return *this; }
    Integer io_manip; ///< the integer to print
    size_t width = 0; ///< the minimum number of digits to print after the 0x prefix
    bool upperCase_ = false; ///< output in uppercase?
};

template <class Integer>
inline std::ostream &
operator <<(std::ostream &os, const AsHex<Integer> number)
{
    const auto oldFlags = os.flags();
    const auto savedFill = os.fill('0');
    if (number.upperCase_)
        os << std::uppercase;
    os << std::hex <<
        std::setw(number.width) <<
        number.io_manip <<
        std::setw(0);
    os.fill(savedFill);
    os.setf(oldFlags);
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

public:
    const Container &container; ///< zero or more items to print

    const char *prefix = nullptr; ///< \copydoc prefixedBy()
    const char *suffix = nullptr; ///< \copydoc suffixedBy()
    const char *delimiter = nullptr; ///< \copydoc delimitedBy()
};

template <class Container>
inline std::ostream &
operator <<(std::ostream &os, const AsList<Container> &manipulator)
{
    bool opened = false;
    for (const auto &item: manipulator.container) {
        if (!opened) {
            if (manipulator.prefix)
                os << manipulator.prefix;
            opened = true;
        } else {
            if (manipulator.delimiter)
                os << manipulator.delimiter;
        }
        os << item;
    }
    if (opened && manipulator.suffix)
        os << manipulator.suffix;
    return os;
}

/// a helper to ease AsList object creation
template <typename Container>
inline auto asList(const Container &c) { return AsList<Container>(c); }

#endif /* SQUID_SRC_BASE_IO_MANIP_H */

