/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_SESSION_H
#define SQUID_SRC_SECURITY_SESSION_H

#include "base/HardFun.h"
#include "comm/forward.h"
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

/// Creates TLS Client connection structure (aka 'session' state) and initializes TLS/SSL I/O (Comm and BIO).
/// On errors, emits DBG_IMPORTANT with details and returns false.
bool CreateClientSession(const Security::ContextPointer &, const Comm::ConnectionPointer &, const char *squidCtx);

/// Creates TLS Server connection structure (aka 'session' state) and initializes TLS/SSL I/O (Comm and BIO).
/// On errors, emits DBG_IMPORTANT with details and returns false.
bool CreateServerSession(const Security::ContextPointer &, const Comm::ConnectionPointer &, const char *squidCtx);

#if USE_OPENSSL
typedef std::shared_ptr<SSL> SessionPointer;

typedef std::unique_ptr<SSL_SESSION, HardFun<void, SSL_SESSION*, &SSL_SESSION_free>> SessionStatePointer;

#elif USE_GNUTLS
typedef std::shared_ptr<struct gnutls_session_int> SessionPointer;

// wrapper function to get around gnutls_free being a typedef
inline void squid_gnutls_free(void *d) {gnutls_free(d);}
typedef std::unique_ptr<gnutls_datum_t, HardFun<void, void*, &Security::squid_gnutls_free>> SessionStatePointer;

#else
typedef std::shared_ptr<void> SessionPointer;

typedef std::unique_ptr<int> SessionStatePointer;

#endif

/// close an active TLS session.
/// set fdOnError to the connection FD when the session is being closed
/// due to an encryption error, otherwise omit.
void SessionClose(const Security::SessionPointer &, int fdOnError = -1);

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

