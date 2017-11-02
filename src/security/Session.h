/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

/// send the shutdown/bye notice for an active TLS session.
void SessionSendGoodbye(const Security::SessionPointer &);

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

#if USE_OPENSSL
// TODO: remove from public API. It is only public because of Security::ServerOptions::updateContextConfig
/// Setup the given TLS context with callbacks used to manage the session cache
void SetSessionCacheCallbacks(Security::ContextPointer &);

/// Helper function to retrieve a (non-locked) ContextPointer from a SessionPointer
inline Security::ContextPointer
GetFrom(Security::SessionPointer &s)
{
    auto *ctx = SSL_get_SSL_CTX(s.get());
    return Security::ContextPointer(ctx, [](SSL_CTX *) {/* nothing to unlock/free */});
}

/// \deprecated use the PeerOptions/ServerOptions API methods instead.
/// Wraps SessionPointer value creation to reduce risk of
/// a nasty hack in ssl/support.cc.
Security::SessionPointer NewSessionObject(const Security::ContextPointer &);
#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SESSION_H */

