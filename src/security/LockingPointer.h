/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_LOCKINGPOINTER_H
#define SQUID_SRC_SECURITY_LOCKINGPOINTER_H

#include "base/Assure.h"
#include "base/HardFun.h"

#if USE_OPENSSL
#include "compat/openssl.h"
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

#endif /* USE_OPENSSL */

// Macro to be used to define the C++ equivalent function of an extern "C"
// function. The C++ function suffixed with the _cpp extension
#define CtoCpp1(function, argument) \
        extern "C++" inline void function ## _cpp(argument a) { \
            function(a); \
        }

namespace Security
{

inline bool nilFunction(const void *) { return false; }
typedef HardFun<bool, const void *, nilFunction> NilFunctor;

/**
 * A shared pointer to a reference-counting Object with library-specific
 * absorption, locking, and unlocking implementations. The API largely
 * follows std::shared_ptr.
 *
 * The constructor and the resetWithoutLocking() method import a raw Object pointer.
 * Normally, reset() would lock(), but libraries like OpenSSL
 * pre-lock objects before they are fed to LockingPointer, necessitating
 * this resetWithoutLocking() customization hook.
 */
template <typename T, void (*UnLocker)(T *t), class Locker = NilFunctor>
class LockingPointer
{
public:
    /// a helper label to simplify this objects API definitions below
    typedef Security::LockingPointer<T, UnLocker, Locker> SelfType;

    /// constructs a nil smart pointer
    constexpr LockingPointer(): raw(nullptr) {}

    /// constructs a nil smart pointer from nullptr
    constexpr LockingPointer(std::nullptr_t): raw(nullptr) {}

    /**
     * Construct directly from a (possibly nil) raw pointer. If the supplied
     * pointer is not nil, it is expected that its producer has already created
     * one reference lock for the object pointed to, and our destructor will do
     * the matching unlock.
     */
    explicit LockingPointer(T *t): raw(nullptr) {
        // de-optimized for clarity about non-locking
        resetWithoutLocking(t);
    }

    /// use the custom UnLocker to unlock any value still stored.
    ~LockingPointer() { unlock(); }

    // copy semantics are okay only when adding a lock reference
    LockingPointer(const SelfType &o) : raw(nullptr) {
        resetAndLock(o.get());
    }
    const SelfType &operator =(const SelfType &o) {
        resetAndLock(o.get());
        return *this;
    }

    LockingPointer(SelfType &&o) : raw(nullptr) {
        resetWithoutLocking(o.release());
    }
    SelfType &operator =(SelfType &&o) {
        if (o.get() != raw)
            resetWithoutLocking(o.release());
        return *this;
    }

    bool operator !() const { return !raw; }
    explicit operator bool() const { return raw; }
    bool operator ==(const SelfType &o) const { return (o.get() == raw); }
    bool operator !=(const SelfType &o) const { return (o.get() != raw); }

    T &operator *() const { Assure(raw); return *raw; }
    T *operator ->() const { return raw; }

    /// Returns raw and possibly nullptr pointer
    T *get() const { return raw; }

    /// Reset raw pointer - unlock any previous one and save new one without locking.
    void resetWithoutLocking(T *t) {
        unlock();
        raw = t;
    }

    void resetAndLock(T *t) {
        if (t != get()) {
            resetWithoutLocking(t);
            lock(t);
        }
    }

    /// Forget the raw pointer - unlock if any value was set. Become a nil pointer.
    void reset() { unlock(); }

    /// Forget the raw pointer without unlocking it. Become a nil pointer.
    T *release() {
        T *ret = raw;
        raw = nullptr;
        return ret;
    }

private:
    /// The lock() method increments Object's reference counter.
    void lock(T *t) {
        if (t) {
            Locker doLock;
            doLock(t);
        }
    }

    /// Become a nil pointer. Decrements any pointed-to Object's reference counter
    /// using UnLocker which ideally destroys the object when the counter reaches zero.
    void unlock() {
        if (raw) {
            UnLocker(raw);
            raw = nullptr;
        }
    }

    /**
     * Normally, no other code will have this raw pointer.
     *
     * However, OpenSSL does some strange and not always consistent things.
     * OpenSSL library may keep its own internal raw pointers and manage
     * their reference counts independently, or it may not. This varies between
     * API functions, though it is usually documented.
     *
     * This means the caller code needs to be carefully written to use the correct
     * reset method and avoid the raw-pointer constructor unless OpenSSL function
     * producing the pointer is clearly documented as incrementing a lock for it.
     */
    T *raw;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_LOCKINGPOINTER_H */

