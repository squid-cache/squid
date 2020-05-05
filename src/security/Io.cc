/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS io management */

#include "squid.h"
#include "fde.h"
#include "security/Io.h"

namespace Security {
    template <typename Fun>
    static IoResult GuardedIo(Comm::Connection &, ErrorCode, Fun);

    typedef SessionPointer::element_type *ConnectionPointer;
}

/// Calls the given TLS I/O function and analysis its outcome.
/// Handles alert logging and reaching supposedly unreachable I/O code.
template <typename Fun>
static Security::IoResult
Security::GuardedIo(Comm::Connection &transport, const ErrorCode topError, Fun ioCall)
{
    assert(transport.isOpen());
    const auto fd = transport.fd;
    auto connection = fd_table[fd].ssl.get();

    // reset and capture errno before anybody else can overwrite it
    errno = 0;
    const auto rawResult = ioCall(connection);
    const auto xerrno = errno;

    debugs(83, 5, rawResult << '/' << xerrno << " for TLS connection " <<
           static_cast<void*>(connection) << " over " << transport);

#if USE_OPENSSL
    if (rawResult > 0)
        return IoResult(IoResult::ioSuccess);

    const auto ssl_error = SSL_get_error(connection, rawResult);

    // quickly handle common, non-erroneous outcomes
    switch (ssl_error) {

    case SSL_ERROR_WANT_READ:
        return IoResult(IoResult::ioWantRead);

    case SSL_ERROR_WANT_WRITE:
        return IoResult(IoResult::ioWantWrite);

    default:
        ; // fall through to handle the problem
    }

    // now we know that we are dealing with a real problem; detail it
    const Ssl::ErrorDetail::Pointer errorDetail = (new Ssl::ErrorDetail(topError))
        ->sysError(xerrno) // see the comment about errno below
        ->ioError(ssl_error)
        ->absorbStackedErrors();

    // We could restrict errno collection to cases where ssl_error is
    // SSL_ERROR_SYSCALL, ssl_lib_error is 0, and rawResult is negative, but we
    // do not do that in hope that all other cases will either have a useful
    // errno or a zero errno. The caller is expected to reset errno before I/O.

    IoResult ioResult(errorDetail);

    // collect debugging-related details
    switch (ssl_error) {
    case SSL_ERROR_SYSCALL:
        if (rawResult == 0) {
            ioResult.errorDescription = "peer aborted";
        } else {
            ioResult.errorDescription = "system call failure";
            ioResult.important = (xerrno == ECONNRESET);
        }
        break;

    case SSL_ERROR_ZERO_RETURN:
        // peer sent a "close notify" alert, closing TLS connection for writing
        ioResult.errorDescription = "peer closed";
        ioResult.important = true;
        break;

    default:
        // an ever-increasing number of possible cases but usually SSL_ERROR_SSL
        ioResult.errorDescription = "failure";
        ioResult.important = true;
    }

    return ioResult;

#elif USE_GNUTLS
    if (rawResult == GNUTLS_E_SUCCESS) {
        // TODO: Avoid gnutls_*() calls if debugging is off.
        const auto desc = gnutls_session_get_desc(connection);
        debugs(83, 2, "TLS session info: " << desc);
        gnutls_free(desc);
        return IoResult(IoResult::ioSuccess);
    }

    // Debug the TLS connection state so far.
    // TODO: Avoid gnutls_*() calls if debugging is off.
    const auto descIn = gnutls_handshake_get_last_in(connection);
    debugs(83, 2, "handshake IN: " << gnutls_handshake_description_get_name(descIn));
    const auto descOut = gnutls_handshake_get_last_out(connection);
    debugs(83, 2, "handshake OUT: " << gnutls_handshake_description_get_name(descOut));

    if (rawResult == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        const auto alert = gnutls_alert_get(connection);
        debugs(83, DBG_IMPORTANT, "WARNING: TLS alert: " << gnutls_alert_get_name(alert));
        // fall through to retry
    }

    if (!gnutls_error_is_fatal(rawResult)) {
        const auto reading = gnutls_record_get_direction(connection) == 0;
        return IoResult(reading ? IoResult::ioWantRead : IoResult::ioWantWrite);
    }

    // now we know that we are dealing with a real problem; detail it
    const ErrorDetail::Pointer errorDetail = (new Ssl::ErrorDetail(topError))
        ->sysError(xerrno)
        ->ioError(rawResult)
        ->absorbStackedErrors();
    IoResult ioResult(errorDetail);

    ioResult.errorDescription = "failure";
    return ioResult;

#else
    // TLS I/O code path should never be reachable without a TLS/SSL library.
    debugs(1, DBG_CRITICAL, ForceAlert << "BUG: " <<
           "Unexpected TLS I/O in Squid built without a TLS/SSL library");
    assert(false); // we want a stack trace which fatal() does not produce
    return IoResult(Ssl::ErrorDetail::Pointer(nullptr)); // not reachable
#endif
}

// TODO: After dropping OpenSSL v1.1.0 support, this and Security::Connect() can
// be simplified further by using SSL_do_handshake() and eliminating lambdas.
Security::IoResult
Security::Accept(Comm::Connection &transport)
{
    return GuardedIo(transport, SQUID_TLS_ERR_ACCEPT, [] (ConnectionPointer tlsConn) -> auto {
#if USE_OPENSSL
        return SSL_accept(tlsConn);
#elif USE_GNUTLS
        return gnutls_handshake(tlsConn);
#else
        return sizeof(tlsConn); // the value is unused; should be unreachable
#endif
    });
}

/// establish a TLS connection over the specified from-Squid transport connection
Security::IoResult
Security::Connect(Comm::Connection &transport)
{
    return GuardedIo(transport, SQUID_TLS_ERR_CONNECT, [] (ConnectionPointer tlsConn) -> auto {
#if USE_OPENSSL
        return SSL_connect(tlsConn);
#elif USE_GNUTLS
        return gnutls_handshake(tlsConn);
#else
        return sizeof(tlsConn); // the value is unused; should be unreachable
#endif
    });
}
