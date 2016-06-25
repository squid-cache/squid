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
 * A pointer that deletes the object it points to when the pointer's owner or
 * context is gone.
 * Maintains locking using OpenSSL crypto API when exporting the stored value
 * between objects.
 * Prevents memory leaks in the presence of exceptions and processing short
 * cuts.
 */
template <typename T, void (*DeAllocator)(T *t), int lock>
class LockingPointer
{
public:
    /// a helper label to simplify this objects API definitions below
    typedef LockingPointer<T, DeAllocator, lock> SelfType;

    /**
     * Construct directly from a raw pointer.
     * This action requires that the producer of that pointer has already
     * created one reference lock for the object pointed to.
     * Our destructor will do the matching unlock/free.
     */
    explicit LockingPointer(T *t = nullptr): raw(t) {}

    /// use the custom DeAllocator to unlock and/or free any value still stored.
    ~LockingPointer() { deletePointer(); }

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

    /// Reset raw pointer - delete last one and save new one.
    void reset(T *t) {
        deletePointer();
        raw = t;
    }

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

    /// Forget the raw pointer without freeing it. Become a nil pointer.
    T *release() {
        T *ret = raw;
        raw = nullptr;
        return ret;
    }

private:
    /// Deallocate raw pointer. Become a nil pointer.
    void deletePointer() {
        if (raw)
            DeAllocator(raw);
        raw = nullptr;
    }

    T *raw; ///< pointer to T object or nullptr
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_LOCKINGPOINTER_H */

