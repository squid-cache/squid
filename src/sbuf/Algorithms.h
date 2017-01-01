/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFALGOS_H_
#define SQUID_SBUFALGOS_H_

#include "sbuf/SBuf.h"

#include <algorithm>
#include <numeric>

/// SBuf equality predicate for STL algorithms etc
class SBufEqual
{
public:
    explicit SBufEqual(const SBuf &reference, SBufCaseSensitive sensitivity = caseSensitive) :
        reference_(reference), sensitivity_(sensitivity) {}
    bool operator() (const SBuf & checking) { return checking.compare(reference_,sensitivity_) == 0; }
private:
    SBuf reference_;
    SBufCaseSensitive sensitivity_;
};

/// SBuf "starts with" predicate for STL algorithms etc
class SBufStartsWith
{
public:
    explicit SBufStartsWith(const SBuf &prefix, SBufCaseSensitive sensitivity = caseSensitive) :
        prefix_(prefix), sensitivity_(sensitivity) {}
    bool operator() (const SBuf & checking) { return checking.startsWith(prefix_,sensitivity_); }
private:
    SBuf prefix_;
    SBufCaseSensitive sensitivity_;
};

/** SBuf size addition accumulator for STL contaniners
 *
 * Equivalent to prefix_length +  SBuf.length() +  separator.length()
 */
class SBufAddLength
{
public:
    explicit SBufAddLength(const SBuf &separator) :
        separatorLen_(separator.length()) {}
    SBuf::size_type operator()(const SBuf::size_type sz, const SBuf & item) {
        return sz + item.length() + separatorLen_;
    }
private:
    SBuf::size_type separatorLen_;
};

/// join all the SBuf in a container of SBuf into a single SBuf, separating with separator
template <class Container>
SBuf
SBufContainerJoin(const Container &items, const SBuf& separator)
{
    // optimization: pre-calculate needed storage
    const SBuf::size_type sz = std::accumulate(items.begin(), items.end(), 0, SBufAddLength(separator));

    // sz can be zero in two cases: either items is empty, or all items
    //  are zero-length. In the former case, we must protect against
    //  dereferencing the iterator later on, and checking sz is more efficient
    //  than checking items.size(). This check also provides an optimization
    //  for the latter case without adding complexity.
    if (sz == 0)
        return SBuf();

    SBuf rv;
    rv.reserveSpace(sz);

    typename Container::const_iterator i(items.begin());
    rv.append(*i);
    ++i;
    for (; i != items.end(); ++i)
        rv.append(separator).append(*i);
    return rv;
}

namespace std {
/// default hash functor to support std::unordered_map<SBuf,*>
template <>
struct hash<SBuf>
{
    size_t operator()(const SBuf &) const noexcept;
};
}

/** hash functor for SBufs, meant so support case-insensitive std::unordered_map
 *
 * Typical use:
 * \code
 * auto m = std::unordered_map<SBuf, ValueType, CaseInsensitiveSBufHash>();
 * \endcode
 */
class CaseInsensitiveSBufHash
{
public:
    std::size_t operator()(const SBuf &) const noexcept;
};

#endif /* SQUID_SBUFALGOS_H_ */

