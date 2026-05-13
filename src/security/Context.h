/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CONTEXT_H
#define SQUID_SRC_SECURITY_CONTEXT_H

#include <memory>

#if USE_OPENSSL
#include "compat/openssl.h"
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#elif HAVE_LIBGNUTLS
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#endif

namespace Security {

#if USE_OPENSSL
using ContextPointer = std::shared_ptr<SSL_CTX>;
#elif HAVE_LIBGNUTLS
using ContextPointer = std::shared_ptr<struct gnutls_certificate_credentials_st>;
#else
// use void* so we can check against nullptr
using ContextPointer = std::shared_ptr<void>;
#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CONTEXT_H */
