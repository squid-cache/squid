/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_POOLINGALLOCATOR_H
#define SQUID_SRC_MEM_POOLINGALLOCATOR_H

#include "mem/forward.h"

#include <utility>

/// STL Allocator that uses Squid memory pools for memory management
template <class Value>
class PoolingAllocator
{
public:
    /* STL Allocator API */
    using value_type = Value;
    PoolingAllocator() noexcept {}
    template <class Other> PoolingAllocator(const PoolingAllocator<Other> &) noexcept {}
    value_type *allocate(std::size_t n) { return static_cast<value_type*>(memAllocBuf(n*sizeof(value_type), nullptr)); }
    void deallocate(value_type *vp, std::size_t n) noexcept { memFreeBuf(n*sizeof(value_type), vp); }

    template <class OtherValue>
    struct rebind {
        typedef PoolingAllocator<OtherValue> other;
    };

    template<class U, class ... Args> void construct(U *p, Args && ... args) { new((void *)p) U(std::forward<Args>(args)...); }
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

#endif /* SQUID_SRC_MEM_POOLINGALLOCATOR_H */

