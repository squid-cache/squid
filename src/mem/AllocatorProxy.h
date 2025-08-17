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
#include "mem/Pool.h"

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
    static inline Mem::Allocator &Pool() { \
        static auto *thePool = MemPools::GetInstance().create(#CLASS, sizeof(CLASS)); \
        thePool->zeroBlocks(false); \
        return *thePool; \
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

#endif /* SQUID_SRC_MEM_ALLOCATORPROXY_H */
