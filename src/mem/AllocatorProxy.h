/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_MEM_ALLOCATORPROXY_H
#define _SQUID_SRC_MEM_ALLOCATORPROXY_H

class MemAllocator;
class MemPoolStats;
class MemPoolMeter;

/**
 * \hideinitializer
 *
 * Pool and account the memory used for the CLASS object.
 * This macro is intended for use within the declaration of a class.
 */
#define MEMPROXY_CLASS(CLASS) \
    private: \
    static inline Mem::AllocatorProxy &Pool() { \
        static Mem::AllocatorProxy thePool(#CLASS, sizeof(CLASS)); \
        return thePool; \
    } \
    public: \
    void *operator new(size_t byteCount) { \
        /* derived classes with different sizes must implement their own new */ \
        assert(byteCount == sizeof(CLASS)); \
        return Pool().alloc(); \
    } \
    void operator delete(void *address) {Pool().freeOne(address);} \
    private:

namespace Mem
{

/**
 * Support late binding of pool type for allocator agnostic classes
 */
class AllocatorProxy
{
public:
    AllocatorProxy(char const *aLabel, size_t const &aSize):
        label(aLabel),
        size(aSize),
        theAllocator(NULL)
    {}

    /// Allocate one element from the pool
    void *alloc();

    /// Free a element allocated by Mem::AllocatorProxy::alloc()
    void freeOne(void *);

    int inUseCount() const;
    size_t objectSize() const {return size;}
    char const * objectType() const {return label;}

    MemPoolMeter const &getMeter() const;

    /**
     * \param stats	Object to be filled with statistical data about pool.
     * \retval		Number of objects in use, ie. allocated.
     */
    int getStats(MemPoolStats * stats);

private:
    MemAllocator *getAllocator() const;

    const char *label;
    size_t size;
    mutable MemAllocator *theAllocator;
};

} // namespace Mem

#endif /* _SQUID_SRC_MEM_ALLOCATORPROXY_H */
