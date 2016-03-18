/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CONTEXT_H
#define SQUID_SRC_SECURITY_CONTEXT_H

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

/* IMPORTANT:
 * Due to circular dependency issues between ssl/libsslsquid.la and
 * security/libsecurity.la the code within src/ssl/ is restricted to
 * only using Security::ContextPtr, it MUST NOT use ContextPointer
 *
 * Code outside of src/ssl/ should always use Security::ContextPointer
 * when storing a reference to a context.
 */
#if USE_OPENSSL
typedef SSL_CTX* ContextPtr;
CtoCpp1(SSL_CTX_free, SSL_CTX *);
typedef LockingPointer<SSL_CTX, SSL_CTX_free_cpp, CRYPTO_LOCK_SSL_CTX> ContextPointer;

#elif USE_GNUTLS
typedef gnutls_certificate_credentials_t ContextPtr;
CtoCpp1(gnutls_certificate_free_credentials, gnutls_certificate_credentials_t);
typedef Security::LockingPointer<struct gnutls_certificate_credentials_st, gnutls_certificate_free_credentials_cpp, -1> ContextPointer;

#else
// use void* so we can check against nullptr
typedef void* ContextPtr;
typedef Security::LockingPointer<void, nullptr, -1> ContextPointer;

#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CONTEXT_H */

