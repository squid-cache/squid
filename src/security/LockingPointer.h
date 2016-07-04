/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_LOCKINGPOINTER_H
#define SQUID_SRC_SECURITY_LOCKINGPOINTER_H

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

#endif /* USE_OPENSSL */

// Macro to be used to define the C++ equivalent function of an extern "C"
// function. The C++ function suffixed with the _cpp extension
#define CtoCpp1(function, argument) \
        extern "C++" inline void function ## _cpp(argument a) { \
            function(a); \
        }

namespace Security
{

/**
 * A shared pointer to a reference-counting Object with library-specific
 * absorption, locking, and unlocking implementations. The API largely
 * follows std::shared_ptr.
 *
 * The constructor and the reset() method import a raw Object pointer.
 * Normally, reset() would lock(), but libraries like OpenSSL
 * pre-lock objects before they are fed to LockingPointer, necessitating
 * this customization hook.
 *
 * The lock() method increments Object's reference counter.
 *
 * The unlock() method decrements Object's reference counter and destroys
 * the object when the counter reaches zero.
 */
template <typename T, void (*UnLocker)(T *t), int lockId>
class LockingPointer
{
public:
    /// a helper label to simplify this objects API definitions below
    typedef LockingPointer<T, UnLocker, lockId> SelfType;

    /**
     * Construct directly from a raw pointer.
     * This action requires that the producer of that pointer has already
     * created one reference lock for the object pointed to.
     * Our destructor will do the matching unlock.
     */
    explicit LockingPointer(T *t = nullptr): raw(t) {}

    /// use the custom UnLocker to unlock any value still stored.
    ~LockingPointer() { unlock(); }

    // copy semantics are okay only when adding a lock reference
    explicit LockingPointer(const SelfType &o) : raw(nullptr) { resetAndLock(o.get()); }
    SelfType &operator =(const SelfType & o) {
        resetAndLock(o.get());
        return *this;
    }

    // move semantics are definitely okay, when possible
    explicit LockingPointer(SelfType &&) = default;
    SelfType &operator =(SelfType &&o) {
        if (o.get() != raw)
            reset(o.release());
        return *this;
    }

    bool operator !() const { return !raw; }
    explicit operator bool() const { return raw; }

    /// Returns raw and possibly nullptr pointer
    T *get() const { return raw; }

    /// Reset raw pointer - unlock any previous one and save new one without locking.
    void reset(T *t) {
        unlock();
        raw = t;
    }

    void resetAndLock(T *t) {
        if (t != get()) {
            reset(t);
            lock(t);
        }
    }

    /// Forget the raw pointer without unlocking it. Become a nil pointer.
    T *release() {
        T *ret = raw;
        raw = nullptr;
        return ret;
    }

private:
    void lock(T *t) {
#if USE_OPENSSL
            if (t)
                CRYPTO_add(&t->references, 1, lockId);
#elif USE_GNUTLS
            // XXX: GnuTLS does not provide locking ?
#else
            assert(false);
#endif
    }

    /// Unlock the raw pointer. Become a nil pointer.
    void unlock() {
        if (raw)
            UnLocker(raw);
        raw = nullptr;
    }

    T *raw; ///< pointer to T object or nullptr
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_LOCKINGPOINTER_H */

