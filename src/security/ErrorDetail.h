/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_ERRORDETAIL_H
#define SQUID_SRC_SECURITY_ERRORDETAIL_H

#include "base/RefCount.h"
#include "error/Detail.h"
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
    ErrorDetail(ErrorCode err_no, const CertPointer &peer, const CertPointer &broken, const char *aReason = nullptr);

#if USE_OPENSSL
    /// Details (or starts detailing) a non-validation failure.
    /// \param anIoErrorNo TLS I/O function outcome; \see ErrorDetail::ioErrorNo
    /// \param aSysErrorNo saved errno(3); \see ErrorDetail::sysErrorNo
    ErrorDetail(ErrorCode anErrorCode, int anIoErrorNo, int aSysErrorNo);
#elif USE_GNUTLS
    /// Details (or starts detailing) a non-validation failure.
    /// \param anLibErrorNo TLS function outcome; \see ErrorDetail::lib_error_no
    /// \param aSysErrorNo saved errno(3); \see ErrorDetail::sysErrorNo
    ErrorDetail(ErrorCode anErrorCode, LibErrorCode aLibErrorNo, int aSysErrorNo);
#endif

    /* ErrorDetail API */
    SBuf brief() const override;
    SBuf verbose(const HttpRequestPointer &) const override;

    /// \returns error category; \see ErrorCode
    ErrorCode errorNo() const { return error_no; }

    /// \returns the previously saved errno(3) or zero
    int sysError() const { return sysErrorNo; }

    /* Certificate manipulation API. TODO: Add GnuTLS implementations, users. */

    /// the peer certificate (or nil)
    Certificate *peerCert() { return peer_cert.get(); }

    /// peer or intermediate certificate that failed validation (or nil)
    Certificate *brokenCert() {return broken_cert.get(); }

    /// remember the SSL certificate of our peer; requires nil peerCert()
    /// unlike the cert-setting constructor, does not assume the cert is bad
    void setPeerCertificate(const CertPointer &);

private:
    ErrorDetail(ErrorCode err, int aSysErrorNo);

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

    CertPointer peer_cert; ///< A pointer to the peer certificate
    CertPointer broken_cert; ///< A pointer to the broken certificate (peer or intermediate)

    /// Squid-discovered error, validation error, or zero; \see ErrorCode
    ErrorCode error_no = 0;

    /// TLS library-reported non-validation error or zero; \see LibErrorCode
    LibErrorCode lib_error_no = 0;

    /// errno(3); system call failure code or zero
    int sysErrorNo = 0;

#if USE_OPENSSL
    /// OpenSSL-specific (first-level or intermediate) TLS I/O operation result
    /// reported by SSL_get_error(3SSL) (e.g., SSL_ERROR_SYSCALL) or zero.
    /// Unlike lib_error_no, this error is mostly meant for I/O control and has
    /// no OpenSSL-provided human-friendly text representation.
    int ioErrorNo = 0;

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

/// Dump the given Security::ErrorDetail via a possibly nil pointer (for
/// debugging). Unfortunately, without this, compilers pick generic RefCount<T>
/// operator "<<" overload (with T=Security::ErrorDetail) instead of the
/// overload provided by the parent ErrorDetail class (that we call here).
inline std::ostream &
operator <<(std::ostream &os, const ErrorDetail::Pointer &p)
{
    return operator <<(os, ::ErrorDetail::Pointer(p));
}

} // namespace Security

#endif /* SQUID_SRC_SECURITY_ERRORDETAIL_H */

