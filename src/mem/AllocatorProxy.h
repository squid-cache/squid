/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_ALLOCATORPROXY_H
#define SQUID_SRC_MEM_ALLOCATORPROXY_H

#include "mem/Allocator.h"

/**
 * \hideinitializer
 *
 * Pool and account the memory used for the CLASS object.
 * This macro is intended for use within the declaration of a class.
 *
 * The memory block allocated by operator new is not zeroed; it is the
 * responsibility of users to ensure that constructors correctly
 * initialize all data members.
 */
#define MEMPROXY_CLASS(CLASS) \
    private: \
    static inline Mem::AllocatorProxy &Pool() { \
        static Mem::AllocatorProxy thePool(#CLASS, sizeof(CLASS), false); \
        return thePool; \
    } \
    public: \
    void *operator new(size_t byteCount) { \
        /* derived classes with different sizes must implement their own new */ \
        assert(byteCount == sizeof(CLASS)); \
        return Pool().alloc(); \
    } \
    void operator delete(void *address) { \
        if (address) \
            Pool().freeOne(address); \
    } \
    static int UseCount() { return Pool().getInUseCount(); } \
    private:

namespace Mem
{

/**
 * Support late binding of pool type for allocator agnostic classes
 */
class AllocatorProxy : public Allocator
{
public:
    AllocatorProxy(char const *aLabel, size_t const &aSize, bool doZeroBlocks):
        Allocator(aLabel, doZeroBlocks),
        size(aSize)
    {}

    /* Mem::Allocator API */
    virtual size_t getStats(PoolStats &);
    virtual PoolMeter const &getMeter() const;
    virtual void *alloc();
    virtual void freeOne(void *);
    virtual size_t objectSize() const {return size;}
    virtual int getInUseCount();
    virtual void zeroBlocks(bool);

    /// \copydoc Mem::Allocator::relabel()
    void relabel(const char * const aLabel);

private:
    Allocator *getAllocator() const;

    size_t size = 0;
    mutable Allocator *theAllocator = nullptr;
};

} // namespace Mem

#endif /* SQUID_SRC_MEM_ALLOCATORPROXY_H */

