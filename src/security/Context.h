/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CONTEXT_H
#define SQUID_SRC_SECURITY_CONTEXT_H

#include <memory>

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
typedef std::shared_ptr<SSL_CTX> ContextPointer;

#elif USE_GNUTLS
typedef std::shared_ptr<struct gnutls_certificate_credentials_st> ContextPointer;

#else
// use void* so we can check against nullptr
typedef std::shared_ptr<void> ContextPointer;

#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CONTEXT_H */

