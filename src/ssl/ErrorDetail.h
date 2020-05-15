/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SSL_ERROR_DETAIL_H
#define _SQUID_SSL_ERROR_DETAIL_H

#include "err_detail_type.h"
#include "ErrorDetailManager.h"
#include "http/forward.h"
#include "mem/forward.h"
#include "security/forward.h"

namespace Ssl
{
/**
 * Converts user-friendly error "name" into an Security::ErrorCode
 * and adds it to the provided container (using emplace).
 * This function can handle numeric error numbers as well as names.
 */
bool ParseErrorString(const char *name, Security::Errors &);

/// The Security::ErrorCode code of the error described by  "name".
Security::ErrorCode GetErrorCode(const char *name);

/// \return string representation of a known TLS error (or a raw error code)
/// \param prefixRawCode whether to prefix raw codes with "SSL_ERR="
const char *GetErrorName(Security::ErrorCode value, const bool prefixRawCode = false);

/// A short description of the TLS error "value"
const char *GetErrorDescr(Security::ErrorCode value);

/// \return true if the TLS error is optional and may not be supported by current squid version
bool ErrorIsOptional(const char *name);

// TODO: Move to Security. This interface is meant to be TLS library-agnostic.
/// Details a TLS-related error. Two kinds of errors can be detailed:
/// * certificate validation errors (including built-in and helper-driven) and
/// * TLS logic and I/O errors (detected by Squid or the TLS library).
///
/// The following details may be available (only the first one is required):
/// * for all errors: problem classification (\see Security::ErrorCode)
/// * for all errors: peer certificate
/// * for certificate validation errors: the broken certificate
/// * for certificate validation errors: validation failure reason
/// * for non-validation errors: TLS library-reported error(s)
/// * for non-validation errors: system call errno(3)
class ErrorDetail:  public ::ErrorDetail
{
    MEMPROXY_CLASS(Ssl::ErrorDetail);
public:
    typedef RefCount<ErrorDetail> Pointer;

    /// Details a server-side certificate verification failure.
    /// If `broken` is nil, then the broken certificate is the peer certificate.
    ErrorDetail(Security::ErrorCode err_no, X509 *peer, X509 *broken, const char *aReason = NULL);

    /// Details (or starts detailing) a non-validation failure.
    /// \param anIoErrorNo TLS I/O function outcome; \see ErrorDetail::ioErrorNo
    /// \param aSysErrorNo saved errno(3); \see ErrorDetail::sysErrorNo
    ErrorDetail(Security::ErrorCode anErrorCode, int anIoErrorNo, int aSysErrorNo);

    /// remember SSL certificate of our peer
    /// uses "move" semantics -- the caller does not unlock the certificate
    void absorbPeerCertificate(X509 *cert);

    /// The error no
    Security::ErrorCode errorNo() const {return error_no;}

    /// \returns the previously saved errno(3) or zero
    int sysError() const { return sysErrorNo; }

    /// the peer certificate
    X509 *peerCert() { return peer_cert.get(); }
    /// peer or intermediate certificate that failed validation
    X509 *brokenCert() {return broken_cert.get(); }

    /// \returns whether we should detail ErrorState instead of `them`
    bool takesPriorityOver(const ErrorDetail &them) const {
        // to reduce pointless updates, return false if us is them
        return this->generation < them.generation;
    }

    /* ErrorDetail API */
    virtual SBuf brief() const override;
    virtual SBuf verbose(const HttpRequestPointer &) const override;

private:
    typedef const char * (ErrorDetail::*fmt_action_t)() const;
    /**
     * Holds a formatting code and its conversion method
     */
    class err_frm_code
    {
    public:
        const char *code;             ///< The formatting code
        fmt_action_t fmt_action; ///< A pointer to the conversion method
    };
    static err_frm_code  ErrorFormatingCodes[]; ///< The supported formatting codes

    explicit ErrorDetail(Security::ErrorCode);

    const char *subject() const;
    const char *ca_name() const;
    const char *cn() const;
    const char *notbefore() const;
    const char *notafter() const;
    const char *err_code() const;
    const char *err_descr() const;
    const char *err_lib_error() const;

    int convert(const char *code, const char **value) const;

    static uint64_t Generations; ///< the total number of ErrorDetails ever made
    uint64_t generation; ///< the number of ErrorDetails made before us plus one

    /// error category; \see Security::ErrorCode
    Security::ErrorCode error_no;

    /// Non-validation error reported by the TLS library or zero.
    /// For OpenSSL, this is the result of the first ERR_get_error(3SSL) call,
    /// which `openssl errstr` can expand into details like
    /// `error:1408F09C:SSL routines:ssl3_get_record:http request`.
    unsigned long lib_error_no = SSL_ERROR_NONE;

    /// TLS I/O operation result or zero
    /// For OpenSSL, a SSL_get_error(3SSL) result (e.g., SSL_ERROR_SYSCALL).
    /// For GnuTLS, a result of an I/O function like gnutls_handshake() (e.g., GNUTLS_E_WARNING_ALERT_RECEIVED)
    int ioErrorNo = 0;

    /// errno(3); system call failure code or zero
    int sysErrorNo = 0;

    Security::CertPointer peer_cert; ///< A pointer to the peer certificate
    Security::CertPointer broken_cert; ///< A pointer to the broken certificate (peer or intermediate)
    String errReason; ///< A custom reason for error, else retrieved from OpenSSL.
    mutable ErrorDetailEntry detailEntry;
};

}//namespace Ssl
#endif

