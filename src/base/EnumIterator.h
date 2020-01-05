/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_ENUMITERATOR_H
#define SQUID_BASE_ENUMITERATOR_H

#include <iterator>
#include <type_traits>

/** Shared functionality between forward and reverse enum iterators
 *
 * This class is not very useful by itself, it contains code shared by
 * EnumIterator and ReverseEnumIterator.
 *
 * \see EnumIterator, ReverseEnumIterator
 */
template <typename EnumType>
class EnumIteratorBase : public std::iterator<std::bidirectional_iterator_tag, EnumType>
{
protected:
#if HAVE_STD_UNDERLYING_TYPE
    typedef typename std::underlying_type<EnumType>::type iterator_type;
#else
    typedef int iterator_type;
#endif

public:
    explicit EnumIteratorBase(EnumType e) : current(static_cast<iterator_type>(e)) {}

    bool operator==(const EnumIteratorBase &i) const {
        return current == i.current;
    }

    bool operator!=(const EnumIteratorBase &i) const {
        return current != i.current;
    }

    EnumType operator*() const {
        return static_cast<EnumType>(current);
    }
protected:
    iterator_type current;
};

/** bidirectional iterator over an enum type
 *
 * It can be instantiated using any enum (or C++11 strongly-typed enum)
 * value; the most common expected use scenario has iterators emitted by
 * EnumRange and WholeEnum via standard begin() and end() calls.
 *
 * In order for the iterator to work, it is mandatory that the underlying
 * enum type's representation values be sequential.
 *
 * The iterator does not check for bounds when incrementing or decrementing,
 * that responsibility is left to the caller.
 *
 * \see EnumRange, WholeEnum, ReverseEnumIterator
 */
template <typename EnumType>
class EnumIterator : public EnumIteratorBase<EnumType>
{
public:
    explicit EnumIterator(EnumType e) : EnumIteratorBase<EnumType>(e) {}

    EnumIterator& operator++() {
        ++ EnumIteratorBase<EnumType>::current;
        return *this;
    }

    EnumIterator& operator++(int) {
        EnumIterator rv(*this);
        ++ EnumIteratorBase<EnumType>::current;
        return rv;
    }

    EnumIterator& operator--() {
        -- EnumIteratorBase<EnumType>::current;
        return *this;
    }

    EnumIterator& operator--(int) {
        EnumIterator rv(*this);
        -- EnumIteratorBase<EnumType>::current;
        return rv;
    }
};

/** bidirectional reverse iterator over an enum type
 *
 * It can be instantiated using any enum (or C++11 strongly-typed enum)
 * value; the most common expected use scenario has iterators emitted by
 * EnumRange and WholeEnum via standard rbegin() and rend() calls.
 *
 * In order for the iterator to work, it is mandatory that the underlying
 * enum type's representation values be sequential.
 *
 * The iterator does not check for bounds; behavior is undefined if the iterator
 * is incremented (or decremented) outside the range representing valid
 * enum symbols (remember: an enum is not a data structure).
 *
 * \see EnumRange, WholeEnum, EnumIterator
 */
template <typename EnumType>
class ReverseEnumIterator : public EnumIteratorBase<EnumType>
{
public:
    explicit ReverseEnumIterator(EnumType e) : EnumIteratorBase<EnumType>(e) {}

    // prefix increment
    ReverseEnumIterator& operator++() {
        -- EnumIteratorBase<EnumType>::current;
        return *this;
    }

    // postfix increment
    ReverseEnumIterator& operator++(int) {
        ReverseEnumIterator rv(*this);
        -- EnumIteratorBase<EnumType>::current;
        return rv;
    }

    // prefix decrement
    ReverseEnumIterator& operator--() {
        ++ EnumIteratorBase<EnumType>::current;
        return *this;
    }

    // postfix decrement
    ReverseEnumIterator& operator--(int) {
        ReverseEnumIterator rv(*this);
        ++ EnumIteratorBase<EnumType>::current;
        return rv;
    }
};

/** Class expressing a continuous range of an enum for range-for expressions
 *
 * This class requires that the underlying enum values be represented by
 * continuous values of an integral type.
 * Users will usually not rely on this class directly but on the more convenient
 * EnumRange function
 *
 * \note EnumIterator<enum>(EnumType::firstmember,EnumType::lastmember)
 * will miss EnumType::lastmember while iterating. If you need to iterate
 * over all of EnumType, use class WholeEnum.
 *
 * \see EnumRange, WholeEnum
 */
template <typename EnumType>
class EnumRangeT
{
public:
    typedef EnumIterator<EnumType> iterator;
    typedef ReverseEnumIterator<EnumType> reverse_iterator;
    EnumRangeT(EnumType first, EnumType one_past_last) : begin_(first), end_(one_past_last) { }
    iterator begin() const { return iterator(begin_);}
    iterator end() const { return iterator(end_);}
    reverse_iterator rbegin() const { return ++reverse_iterator(end_); }
    reverse_iterator rend() const { return ++reverse_iterator(begin_); }
private:
    EnumType begin_;
    EnumType end_;
};

/** Generate a continuous range of an enum for range-for expressions
 *
 * convenience function to deduce the right type for instantiating EnumRangeT.
 * See EnumRangeT for more detailed documentation and caveats.
 *
 * Typical use:
 * \code
 * enum class EnumType {
 *   blue, red, yellow, green, pink
 * };
 * for (auto enumvalue : EnumRange(EnumType::red,EnumType::green)) {
 *   do_stuff(enumvalue); // will be called twice, with arguments red and yellow
 * }
 * \endcode
 */
template <typename EnumType>
EnumRangeT<EnumType> EnumRange(EnumType begin, EnumType one_past_end)
{
    return EnumRangeT<EnumType>(begin,one_past_end);
}

/** Class expressing a continuous range of a whole enum for range-for expressions
 *
 * Class for iterating all enum values, from EnumType::enumBegin_ up to, but
 * not including, EnumType::enumEnd_.
 *
 * This class requires that:
 * - the underlying enum values be represented by continuous values of
 *   an integral type.
 * - both enumBegin_ and enumEnd_ markers must be present as EnumType values;
 * - enumBegin_ must have the same representation as the first element of the
 *   enum
 * - enumEnd_ must have a representation that is one past the last
 *   user-accessible value of the enum.
 *
 * Typical use:
 * \code
 * enum class EnumType {
 *   enumBegin_ = 0,
 *   first_value = enumBegin_,
 *   second_value,
 *   enumEnd_
 * };
 * for(auto enumvalue : WholeEnum<EnumType>()) {
 *   do_stuff();
 * }
 * \endcode
 */
template <typename EnumType>
class WholeEnum : public EnumRangeT<EnumType>
{
public:
    WholeEnum() : EnumRangeT<EnumType>(EnumType::enumBegin_, EnumType::enumEnd_) {}
};

#endif /* SQUID_BASE_ENUMITERATOR_H */

