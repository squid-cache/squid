/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_SESSION_H
#define SQUID_SRC_SECURITY_SESSION_H

#include "security/LockingPointer.h"

#include <memory>

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
// Locks can be implemented attaching locks counter to gnutls_session_t
// objects using the gnutls_session_set_ptr()/gnutls_session_get_ptr ()
// library functions
CtoCpp1(gnutls_deinit, gnutls_session_t);
typedef LockingPointer<struct gnutls_session_int, gnutls_deinit_cpp, -1> SessionPointer;

#else
// use void* so we can check against NULL
typedef void* SessionPtr;
CtoCpp1(xfree, SessionPtr);
typedef LockingPointer<void, xfree_cpp, -1> SessionPointer;

#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SESSION_H */

