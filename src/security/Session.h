/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_SESSION_H
#define SQUID_SRC_SECURITY_SESSION_H

// LockingPointer.h instead of TidyPointer.h for CtoCpp1()
#include "security/LockingPointer.h"

#if USE_OPENSSL
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif
#endif

#if USE_GNUTLS
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#endif

namespace Security {

#if USE_OPENSSL
typedef SSL* SessionPtr;
CtoCpp1(SSL_free, SSL *);
typedef LockingPointer<SSL, Security::SSL_free_cpp, CRYPTO_LOCK_SSL> SessionPointer;

#elif USE_GNUTLS
typedef gnutls_session_t SessionPtr;
CtoCpp1(gnutls_deinit, gnutls_session_t);
// TODO: Convert to Locking pointer.
// Locks can be implemented attaching locks counter to gnutls_session_t
// objects using the gnutls_session_set_ptr()/gnutls_session_get_ptr ()
// library functions
typedef TidyPointer<struct gnutls_session_int, Security::gnutls_deinit_cpp> SessionPointer;

#else
// use void* so we can check against NULL
typedef void* SessionPtr;
typedef TidyPointer<void, nullptr> SessionPointer;

#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SESSION_H */

