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
CtoCpp1(SSL_free, SSL *);
#if defined(CRYPTO_LOCK_SSL) // OpenSSL 1.0
inline int SSL_up_ref(SSL *t) {if (t) CRYPTO_add(&t->references, 1, CRYPTO_LOCK_SSL); return 0;}
#endif
typedef Security::LockingPointer<SSL, Security::SSL_free_cpp, HardFun<int, SSL *, SSL_up_ref> > SessionPointer;

typedef std::unique_ptr<SSL_SESSION, HardFun<void, SSL_SESSION*, &SSL_SESSION_free>> SessionStatePointer;

#elif USE_GNUTLS
// Locks can be implemented attaching locks counter to gnutls_session_t
// objects using the gnutls_session_set_ptr()/gnutls_session_get_ptr ()
// library functions
CtoCpp1(gnutls_deinit, gnutls_session_t);
typedef Security::LockingPointer<struct gnutls_session_int, gnutls_deinit_cpp> SessionPointer;

// wrapper function to get around gnutls_free being a typedef
inline void squid_gnutls_free(void *d) {gnutls_free(d);}
typedef std::unique_ptr<gnutls_datum_t, HardFun<void, void*, &Security::squid_gnutls_free>> SessionStatePointer;

#else
// use void* so we can check against NULL
CtoCpp1(xfree, void *);
typedef Security::LockingPointer<void, xfree_cpp> SessionPointer;

typedef std::unique_ptr<int> SessionStatePointer;

#endif

/// whether the session is a resumed one
bool SessionIsResumed(const Security::SessionPointer &);

/**
 * When the session is not a resumed session, retrieve the details needed to
 * resume a later connection and store them in 'data'. This may result in 'data'
 * becoming a nil Pointer if no details exist or an error occurs.
 *
 * When the session is already a resumed session, do nothing and leave 'data'
 * unhanged.
 * XXX: is this latter behaviour always correct?
 */
void MaybeGetSessionResumeData(const Security::SessionPointer &, Security::SessionStatePointer &data);

/// Set the data for resuming a previous session.
/// Needs to be done before using the SessionPointer for a handshake.
void SetSessionResumeData(const Security::SessionPointer &, const Security::SessionStatePointer &);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SESSION_H */

