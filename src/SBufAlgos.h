#ifndef SQUID_SBUFALGOS_H_
#define SQUID_SBUFALGOS_H_

#include "SBuf.h"
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
        separator_len(separator.length()) {}
    SBuf::size_type operator()(const SBuf::size_type sz, const SBuf & item) {
        return sz + item.length() + separator_len;
    }
private:
    SBuf::size_type separator_len;
};

/// join all the SBuf in a container of SBuf into a single SBuf, separating with separator
template <class Container>
SBuf
SBufContainerJoin(const Container &items, const SBuf& separator)
{
    // optimization: pre-calculate needed storage
    const SBuf::size_type sz = std::accumulate(items.begin(), items.end(), 0, SBufAddLength(separator));

    // protect against blindly dereferencing items.begin() if items.size()==0
    if (sz == 0)
        return SBuf();

    SBuf rv;
    rv.reserveSpace(sz);

    typename Container::const_iterator i(items.begin());
    rv.append(*i);
    ++i;
    for (;i != items.end(); ++i)
        rv.append(separator).append(*i);
    return rv;
}

#endif /* SQUID_SBUFALGOS_H_ */
