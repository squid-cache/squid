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

#if USE_OPENSSL
CtoCpp1(SSL_CTX_free, SSL_CTX *);
typedef LockingPointer<SSL_CTX, SSL_CTX_free_cpp, CRYPTO_LOCK_SSL_CTX> ContextPointer;

#elif USE_GNUTLS
CtoCpp1(gnutls_certificate_free_credentials, gnutls_certificate_credentials_t);
typedef Security::LockingPointer<struct gnutls_certificate_credentials_st, gnutls_certificate_free_credentials_cpp, -1> ContextPointer;

#else
// use void* so we can check against nullptr
typedef Security::LockingPointer<void, nullptr, -1> ContextPointer;

#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CONTEXT_H */

