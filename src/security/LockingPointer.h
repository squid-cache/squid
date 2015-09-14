#ifndef SQUID_SRC_SECURITY_LOCKINGPOINTER_H
#define SQUID_SRC_SECURITY_LOCKINGPOINTER_H

#include "base/TidyPointer.h"

namespace Security
{

/**
  * Add SSL locking (a.k.a. reference counting) to TidyPointer
  */
template <typename T, void (*DeAllocator)(T *t), int lock>
class LockingPointer: public TidyPointer<T, DeAllocator>
{
public:
    typedef TidyPointer<T, DeAllocator> Parent;

    LockingPointer(T *t = nullptr): Parent(t) {}

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
