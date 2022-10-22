/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_MEM_ALLOCATORPROXY_H
#define _SQUID_SRC_MEM_ALLOCATORPROXY_H

// XXX: remove AllocatorProxy.h include from mem/forward.h
namespace Mem {
class AllocatorBase;
class PoolMeter;
class PoolStats;
}
class MemAllocator;

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
class AllocatorProxy
{
public:
    AllocatorProxy(char const *aLabel, size_t const &aSize, bool doZeroBlocks = true):
        doZero(doZeroBlocks),
        label(aLabel),
        size(aSize)
    {}

    /* (emulate) Mem::AllocatorBase API */
    int getStats(PoolStats *);
    Mem::PoolMeter const &getMeter() const;
    void *alloc();
    void freeOne(void *);
    char const * objectType() const {return label;}
    size_t objectSize() const {return size;}
    int getInUseCount() const;
    void zeroBlocks(bool doIt);
private:
    bool doZero = true;
    const char *label = nullptr;

private:
    AllocatorBase *getAllocator() const;

    size_t size = 0;
    mutable AllocatorBase *theAllocator = nullptr;
};

} // namespace Mem

#endif /* _SQUID_SRC_MEM_ALLOCATORPROXY_H */

