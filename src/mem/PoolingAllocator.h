/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEM_POOLINGALLOCATOR_H
#define SQUID_MEM_POOLINGALLOCATOR_H

#include "mem/forward.h"

/// STL Allocator that uses Squid memory pools for memory management
template <class Value>
class PoolingAllocator
{
public:
    /* STL Allocator API */
    using value_type = Value;
    PoolingAllocator() noexcept {}
    template <class Other> PoolingAllocator(const PoolingAllocator<Other> &) noexcept {}
    value_type *allocate(std::size_t n) { return static_cast<value_type*>(memAllocRigid(n*sizeof(value_type))); }
    void deallocate(value_type *vp, std::size_t n) noexcept { memFreeRigid(vp, n*sizeof(value_type)); }

    // The following declarations are only necessary for compilers that do not
    // fully support C++11 Allocator-related APIs, such as GCC v4.8.
    // TODO: Remove after dropping support for such compilers.

    using size_type = size_t;
    using pointer = Value*;
    using const_pointer = const Value*;
    using reference = Value&;
    using const_reference = const Value&;

    template <class OtherValue>
    struct rebind {
        typedef PoolingAllocator<OtherValue> other;
    };

    template<typename OtherValue> void destroy(OtherValue *p) { p->~OtherValue(); }
};

template <class L, class R>
inline bool
operator ==(const PoolingAllocator<L>&, const PoolingAllocator<R>&) noexcept
{
    return true;
}

template <class L, class R>
inline bool
operator !=(const PoolingAllocator<L> &l, const PoolingAllocator<R> &r) noexcept
{
    return !(l == r);
}

#endif /* SQUID_MEM_POOLINGALLOCATOR_H */

