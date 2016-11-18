/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CONTEXT_H
#define SQUID_SRC_SECURITY_CONTEXT_H

#include "security/forward.h"
#include "security/LockingPointer.h"

#if USE_OPENSSL
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#elif USE_GNUTLS
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#endif

namespace Security {

#if USE_OPENSSL
CtoCpp1(SSL_CTX_free, SSL_CTX *);
#if defined(CRYPTO_LOCK_SSL_CTX) // OpenSSL 1.0
inline int SSL_CTX_up_ref(SSL_CTX *t) {if (t) CRYPTO_add(&t->references, 1, CRYPTO_LOCK_SSL_CTX); return 0;}
#endif
typedef Security::LockingPointer<SSL_CTX, SSL_CTX_free_cpp, HardFun<int, SSL_CTX *, SSL_CTX_up_ref> > ContextPointer;

#elif USE_GNUTLS
CtoCpp1(gnutls_certificate_free_credentials, gnutls_certificate_credentials_t);
typedef Security::LockingPointer<struct gnutls_certificate_credentials_st, gnutls_certificate_free_credentials_cpp> ContextPointer;

#else
// use void* so we can check against nullptr
typedef Security::LockingPointer<void, nullptr> ContextPointer;

#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CONTEXT_H */

