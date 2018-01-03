/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DESCRIPTOR_SET_H
#define SQUID_DESCRIPTOR_SET_H

#include <iosfwd>

/** \ingroup Comm

    \todo: Should we use std::set<int> with its flexibility? Our implementation
    has constant overhead, which is smaller than log(n) of std::set.

an unordered collection of unique descriptors with O(1) add/del/has ops */
class DescriptorSet
{
public:
    // for STL compatibility, should we decide to switch to std::set or similar
    typedef const int *const_iterator;

    DescriptorSet();
    ~DescriptorSet();

    /// checks whether fd is in the set
    bool has(const int fd) const {
        return 0 <= fd && fd < capacity_ &&
               index_[fd] >= 0;
    }

    bool add(int fd); ///< adds if unique; returns true if added
    bool del(int fd); ///< deletes if there; returns true if deleted
    int pop(); ///< deletes and returns one descriptor, in unspecified order

    bool empty() const { return !size_; } ///< number of descriptors in the set

    /// begin iterator a la STL; may become invalid if the object is modified
    const_iterator begin() const { return descriptors_; }
    /// end iterator a la STL; may become invalid if the object is modified
    const_iterator end() const { return begin() + size_; }

    /// outputs debugging info about the set
    void print(std::ostream &os) const;

private:
    // these would be easy to support when needed; prohibit for now
    DescriptorSet(const DescriptorSet &s); // declared but undefined
    DescriptorSet &operator =(const DescriptorSet &s); // declared, undefined

    int *descriptors_; ///< descriptor values in random order
    int *index_; ///< descriptor:position index into descriptors_
    int capacity_; ///< total number of descriptor slots
    int size_; ///< number of descriptors in the set
};

/// convenience wrapper to be used in debugs() context
inline std::ostream &
operator <<(std::ostream &os, const DescriptorSet &ds)
{
    ds.print(os);
    return os;
}

#endif /* SQUID_DESCRIPTOR_SET_H */

