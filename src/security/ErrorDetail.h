/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_DETAIL_H
#define SQUID_SRC_SECURITY_DETAIL_H

#include "base/RefCount.h"
#include "err_detail_type.h"
#include "http/forward.h"
#include "security/forward.h"
#include "SquidString.h"

#if USE_OPENSSL
#include "ssl/ErrorDetailManager.h"
#endif

namespace Security {

/// Details a TLS-related error. Two kinds of errors can be detailed:
/// * certificate validation errors (including built-in and helper-driven) and
/// * TLS logic and I/O errors (detected by Squid or the TLS library).
///
/// The following details may be available (only the first one is required):
/// * for all errors: problem classification (\see ErrorCode)
/// * for all errors: peer certificate
/// * for certificate validation errors: the broken certificate
/// * for certificate validation errors: validation failure reason
/// * for non-validation errors: TLS library-reported error(s)
/// * for non-validation errors: system call errno(3)
class ErrorDetail: public ::ErrorDetail
{
    MEMPROXY_CLASS(Security::ErrorDetail);

public:
    typedef ErrorDetailPointer Pointer;

    /// Details a server-side certificate verification failure.
    /// If `broken` is nil, then the broken certificate is the peer certificate.
    ErrorDetail(ErrorCode err_no, Certificate *peer, Certificate *broken, const char *aReason = NULL);

    /// Details (or starts detailing) a non-validation failure.
    /// \param anIoErrorNo TLS I/O function outcome; \see ErrorDetail::ioErrorNo
    /// \param aSysErrorNo saved errno(3); \see ErrorDetail::sysErrorNo
    ErrorDetail(ErrorCode anErrorCode, int anIoErrorNo, int aSysErrorNo);

    /// \returns whether we (rather than `them`) should detail ErrorState
    bool takesPriorityOver(const ErrorDetail &them) const {
        // to reduce pointless updates, return false if us is them
        return this->generation < them.generation;
    }

    /* ErrorDetail API */
    virtual SBuf brief() const;
    virtual SBuf verbose(const HttpRequestPointer &) const;

    /// \returns error category; \see ErrorCode
    ErrorCode errorNo() const { return error_no; }

    /// \returns the previously saved errno(3) or zero
    int sysError() const { return sysErrorNo; }

    /* Certificate manipulation API. TODO: Add GnuTLS implementations, users. */

    /// remember SSL certificate of our peer
    /// uses "move" semantics -- the caller does not unlock the certificate
    void absorbPeerCertificate(Certificate *cert);

    /// the peer certificate (or nil)
    Certificate *peerCert() { return peer_cert.get(); }

    /// peer or intermediate certificate that failed validation (or nil)
    Certificate *brokenCert() {return broken_cert.get(); }

private:
    explicit ErrorDetail(Security::ErrorCode);

    /* methods for formatting error details using admin-configurable %codes */
    const char *subject() const;
    const char *ca_name() const;
    const char *cn() const;
    const char *notbefore() const;
    const char *notafter() const;
    const char *err_code() const;
    const char *err_descr() const;
    const char *err_lib_error() const;
    size_t convert(const char *code, const char **value) const;

    static uint64_t Generations; ///< the total number of ErrorDetails ever made
    uint64_t generation; ///< the number of ErrorDetails made before us plus one

    CertPointer peer_cert; ///< A pointer to the peer certificate
    CertPointer broken_cert; ///< A pointer to the broken certificate (peer or intermediate)

    /// error category; \see ErrorCode
    ErrorCode error_no = 0;

    /// TLS I/O operation result or zero
    /// For OpenSSL, a SSL_get_error(3SSL) result (e.g., SSL_ERROR_SYSCALL).
    /// For GnuTLS, a result of an I/O function like gnutls_handshake() (e.g., GNUTLS_E_WARNING_ALERT_RECEIVED)
    int ioErrorNo = 0;

    /// errno(3); system call failure code or zero
    int sysErrorNo = 0;

#if USE_OPENSSL
    /// Non-validation error reported by the TLS library or zero.
    /// For OpenSSL, this is the result of the first ERR_get_error(3SSL) call,
    /// which `openssl errstr` can expand into details like
    /// `error:1408F09C:SSL routines:ssl3_get_record:http request`.
    unsigned long lib_error_no = SSL_ERROR_NONE;

    using ErrorDetailEntry = Ssl::ErrorDetailEntry;
    mutable ErrorDetailEntry detailEntry;
#else
    // other TLS libraries do not use custom ErrorDetail members
#endif

    String errReason; ///< a custom reason for the error
};

/// \returns ErrorCode with a given name (or zero)
ErrorCode ErrorCodeFromName(const char *name);

/// \returns string representation of ErrorCode, including raw X.509 error codes
/// \param prefixRawCode whether to prefix raw codes with "SSL_ERR="
const char *ErrorNameFromCode(ErrorCode err, bool prefixRawCode = false);

}

#endif
