/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Comm */

#include "squid.h"
#include "DescriptorSet.h"
#include "globals.h" /* for Squid_MaxFD */

// pre-allocates descriptor store and index for Squid_MaxFD descriptors
DescriptorSet::DescriptorSet(): descriptors_(NULL), index_(NULL),
    capacity_(0), size_(0)
{
    // we allocate once and never realloc, at least for now
    capacity_ = Squid_MaxFD;
    descriptors_ = new int[capacity_];
    index_ = new int[capacity_];

    // fill index with -1s to be able to say whether a descriptor is present
    // it is not essential to fill the descriptors, but it enables more checks
    for (int i = 0; i < capacity_; ++i)
        index_[i] = descriptors_[i] = -1;
}

DescriptorSet::~DescriptorSet()
{
    delete[] descriptors_;
    delete[] index_;
}

/// adds if unique; returns true if added
bool
DescriptorSet::add(int fd)
{
    Must(0 <= fd);
    Must(fd < capacity_);

    if (has(fd))
        return false; // already have it

    Must(size_ < capacity_);
    const int pos = size_;
    ++size_;
    index_[fd] = pos;
    descriptors_[pos] = fd;
    return true; // really added
}

/// deletes if there; returns true if deleted
bool
DescriptorSet::del(int fd)
{
    Must(0 <= fd && fd < capacity_);

    if (!has(fd))
        return false; // we do not have it

    Must(!empty());
    const int delPos = index_[fd];
    Must(0 <= delPos);
    Must(delPos < capacity_);

    // move the last descriptor to the deleted fd position
    // to avoid skipping deleted descriptors in pop()
    const int lastPos = size_-1;
    const int lastFd = descriptors_[lastPos];
    Must(delPos <= lastPos); // may be the same
    descriptors_[delPos] = lastFd;
    index_[lastFd] = delPos;

    descriptors_[lastPos] = -1;
    index_[fd] = -1;
    --size_;

    return true; // really added
}

/// ejects one descriptor in unspecified order
int
DescriptorSet::pop()
{
    assert(!empty());
    const int lastPos =--size_;
    const int lastFd = descriptors_[lastPos];
    assert(0 <= lastFd && lastFd < capacity_);

    // cleanup
    descriptors_[lastPos] = -1;
    index_[lastFd] = -1;

    return lastFd;
}

void
DescriptorSet::print(std::ostream &os) const
{
    // TODO: add "name" if the set is used for more than just half-closed FDs
    os << size_ << " FDs";
}

