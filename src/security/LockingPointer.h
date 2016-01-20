/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_LOCKINGPOINTER_H
#define SQUID_SRC_SECURITY_LOCKINGPOINTER_H

#include "base/TidyPointer.h"

#if USE_OPENSSL

#if HAVE_OPENSSL_CRYPTO_H
#include <openssl/crypto.h>
#endif

// Macro to be used to define the C++ wrapper function of a sk_*_pop_free
// openssl family functions. The C++ function suffixed with the _free_wrapper
// extension
#define sk_free_wrapper(sk_object, argument, freefunction) \
        extern "C++" inline void sk_object ## _free_wrapper(argument a) { \
            sk_object ## _pop_free(a, freefunction); \
        }

#else // !USE_OPENSSL

#include "base/Lock.h"
#include <unordered_map>

#endif

// Macro to be used to define the C++ equivalent function of an extern "C"
// function. The C++ function suffixed with the _cpp extension
#define CtoCpp1(function, argument) \
        extern "C++" inline void function ## _cpp(argument a) { \
            function(a); \
        }

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

    explicit LockingPointer(T *t = nullptr): Parent() {reset(t);}

    virtual ~LockingPointer() { Parent::reset(nullptr); }

    explicit LockingPointer(const SelfType &o): Parent() {
        reset(o.get());
    }

    SelfType &operator =(const SelfType & o) {
        reset(o.get());
        return *this;
    }

    explicit LockingPointer(LockingPointer<T, DeAllocator, lock> &&o) : Parent() {
        *(this->addr()) = o.get();
        o.release();
    }

    LockingPointer<T, DeAllocator, lock> &operator =(LockingPointer<T, DeAllocator, lock> &&o) {
        if (o.get() != this->get()) {
            if (this->get()) {
                Parent::reset(o.get());
            } else {
                *(this->addr()) = o.get();
                o.release();
            }
        }
        return *this;
    }

    virtual void reset(T *t) {
        if (t == this->get())
            return;

#if !USE_OPENSSL
        // OpenSSL maintains the reference locks through calls to Deallocator
        // our manual locking does not have that luxury
        if (this->get()) {
            if (SelfType::Locks().at(this->get()).unlock())
                SelfType::Locks().erase(this->get());
        }
#endif
        Parent::reset(t);

        if (t) {
#if USE_OPENSSL
            CRYPTO_add(&t->references, 1, lock);
#else
            SelfType::Locks()[t].lock(); // find/create and lock
#endif
        }
    }

private:
#if !USE_OPENSSL
    // since we can never be sure if a raw-* passed to us is already being
    // lock counted by another LockingPointer<> and the types pointed to are
    // defined by third-party libraries we have to maintain the locks in a
    // type-specific static external to both the Pointer and base classes.
    static std::unordered_map<T*, Lock> & Locks() {
        static std::unordered_map<T*, Lock> Instance;
        return Instance;
    }
#endif
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_LOCKINGPOINTER_H */

