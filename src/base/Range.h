/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_RANGE_H
#define SQUID_SRC_BASE_RANGE_H

#include <iosfwd>
#include <ostream>

/* represents [start, end) */

template <class C, class S = size_t>
class Range
{

public:
    Range ();
    Range (C start_, C end_);
    C start;
    C end;
    Range intersection (Range const &) const;
    bool contains(C const &) const;
    S size() const;
};

template <class C, class S>
std::ostream& operator << (std::ostream &os, Range<C, S> const &aRange)
{
    os << "[" << aRange.start << "," << aRange.end << ")";
    return os;
}

template<class C, class S>
Range<C, S>::Range () : start(), end() {}

template<class C, class S>
Range<C, S>::Range (C start_, C end_) : start(start_), end(end_) {}

template<class C, class S>
Range<C, S>
Range<C, S>::intersection (Range const &rhs) const
{
    Range<C, S> result (max(start, rhs.start), min(end, rhs.end));
    return result;
}

template<class C, class S>
bool
Range<C, S>::contains(C const &value) const {
    assert(start <= end);
    return (start <= value && value <= end);
}

template<class C, class S>
S
Range<C, S>::size() const
{
    return (S) (end > start ? end - start : 0);
}

#endif /* SQUID_SRC_BASE_RANGE_H */

