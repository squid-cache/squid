/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_LOCKINGPOINTER_H
#define SQUID_SRC_SECURITY_LOCKINGPOINTER_H

#include "base/TidyPointer.h"

namespace Security
{

/**
 * Add SSL locking (a.k.a. reference counting) and assignment to TidyPointer
 */
template <typename T, void (*DeAllocator)(T *t), int lock>
class LockingPointer: public TidyPointer<T, DeAllocator>
{
public:
    typedef TidyPointer<T, DeAllocator> Parent;
    typedef LockingPointer<T, DeAllocator, lock> SelfType;

    explicit LockingPointer(T *t = nullptr): Parent(t) {}

    explicit LockingPointer(const SelfType &o): Parent() {
        resetAndLock(o.get());
    }

    SelfType &operator =(const SelfType & o) {
        resetAndLock(o.get());
        return *this;
    }

#if __cplusplus >= 201103L
    explicit LockingPointer(LockingPointer<T, DeAllocator, lock> &&o): Parent(o.get()) {
        *o.addr() = nullptr;
    }

    LockingPointer<T, DeAllocator, lock> &operator =(LockingPointer<T, DeAllocator, lock> &&o) {
        if (o.get() != this->get()) {
            this->reset(o.get());
            *o.addr() = nullptr;
        }
        return *this;
    }
#endif

    void resetAndLock(T *t) {
        if (t != this->get()) {
            this->reset(t);
#if USE_OPENSSL
            if (t)
                CRYPTO_add(&t->references, 1, lock);
#elif USE_GNUTLS
            // XXX: GnuTLS does not provide locking ?
#else
            assert(false);
#endif
        }
    }
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_LOCKINGPOINTER_H */

