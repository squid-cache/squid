/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#ifndef SQUID_SRC_BASE_RAW_H
#define SQUID_SRC_BASE_RAW_H

#include <iostream>
#include <iomanip>

/// Prints raw and/or non-terminated data safely, efficiently, and beautifully.
/// Allows raw data debugging in debugs() statements with low debugging levels
/// by printing only if higher section debugging levels are configured:
///   debugs(11, DBG_IMPORTANT, "always printed" << Raw(may be printed...));
class Raw
{
public:
    Raw(const char *label, const char *data, const size_t size):
        level(-1), label_(label), data_(data), size_(size), useHex_(false), useGap_(true) {}

    /// limit data printing to at least the given debugging level
    Raw &minLevel(const int aLevel) { level = aLevel; return *this; }

    /// print data using two hex digits per byte (decoder: xxd -r -p)
    Raw &hex() { useHex_ = true; return *this; }

    Raw &gap(bool useGap = true) { useGap_ = useGap; return *this; }

    /// If debugging is prohibited by the current debugs() or section level,
    /// prints nothing. Otherwise, dumps data using one of these formats:
    ///   " label[size]=data" if label was set and data size is positive
    ///   " label[0]" if label was set and data size is zero
    ///   " data" if label was not set and data size is positive
    ///   "" (i.e., prints nothing) if label was not set and data size is zero
    std::ostream &print(std::ostream &os) const;

    /// Minimum section debugging level necessary for printing. By default,
    /// small strings are always printed while large strings are only printed
    /// if DBG_DATA debugging level is enabled.
    int level;

private:
    void printHex(std::ostream &os) const;

    const char *label_; ///< optional data name or ID; triggers size printing
    const char *data_; ///< raw data to be printed
    size_t size_; ///< data length
    bool useHex_; ///< whether hex() has been called
    bool useGap_; ///< whether to print leading space if label is missing
};

inline
std::ostream &operator <<(std::ostream &os, const Raw &raw)
{
    return raw.print(os);
}

/// debugs objects pointed by possibly nil pointers: label=object
template <class Pointer>
class RawPointerT {
public:
    RawPointerT(const char *aLabel, const Pointer &aPtr):
        label(aLabel), ptr(aPtr) {}
    const char *label; /// the name or description of the being-debugged object
    const Pointer &ptr; /// a possibly nil pointer to the being-debugged object
};

/// convenience wrapper for creating  RawPointerT<> objects
template <class Pointer>
inline RawPointerT<Pointer>
RawPointer(const char *label, const Pointer &ptr)
{
    return RawPointerT<Pointer>(label, ptr);
}

/// prints RawPointerT<>, dereferencing the raw pointer if possible
template <class Pointer>
inline std::ostream &
operator <<(std::ostream &os, const RawPointerT<Pointer> &pd)
{
    os << pd.label << '=';
    if (pd.ptr)
        return os << *pd.ptr;
    else
        return os << "[nil]";
}

/// std::ostream manipulator to print integers as hex numbers prefixed by 0x
template <class Integer>
class AsHex
{
public:
    explicit AsHex(const Integer n): raw(n) {}
    Integer raw; ///< the integer to print
};

template <class Integer>
inline std::ostream &
operator <<(std::ostream &os, const AsHex<Integer> number)
{
    const auto oldFlags = os.flags();
    os << std::hex << std::showbase << number.raw;
    os.setf(oldFlags);
    return os;
}

/// a helper to ease AsHex object creation
template <class Integer>
inline AsHex<Integer> asHex(const Integer n) { return AsHex<Integer>(n); }

/// Prints the first n data bytes using hex notation. Does nothing if n is 0.
void PrintHex(std::ostream &, const char *data, size_t n);

#endif /* SQUID_SRC_BASE_RAW_H */

