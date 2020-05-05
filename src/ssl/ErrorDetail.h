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
/// Details a TLS-related error. Three kinds of errors can be detailed:
/// * certificate validation errors (including built-in and helper-driven),
/// * I/O errors,
/// * general handling/logic errors (detected by Squid or the TLS library).
///
/// The following details may be available (only the first one is required):
/// * for all errors: Squid-specific error classification (ErrorCode)
/// * for all errors: peer certificate
/// * for non-validation errors: TLS library-reported error(s)
/// * for certificate validation errors: the broken certificate
/// * for certificate validation errors: validation failure reason
/// * for I/O errors: system errno(3)
///
/// Currently, Squid treats TLS library-returned validation errors (e.g.
/// X509_V_ERR_INVALID_CA) as Squid-specific error classification.
class ErrorDetail:  public ::ErrorDetail
{
    MEMPROXY_CLASS(Ssl::ErrorDetail);
public:
    typedef RefCount<ErrorDetail> Pointer;

    /// Used for server-side TLS certificate verification failures to
    /// detail server certificates and provide extra string describing
    /// the failure.
    /// If the broken certificate is nil then the broken certificate is
    /// the peer certificate.
    ErrorDetail(Security::ErrorCode err_no, X509 *peer, X509 *broken, const char *aReason = NULL);

    /// General TLS handshake failures or failures due to TLS/SSL
    /// library errors
    ErrorDetail(Security::ErrorCode err_no, unsigned long lib_err);
    explicit ErrorDetail(const Security::ErrorCode err_no);

    /// remember errno(3)
    void sysError(const int xerrno) { sysErrorNo = xerrno; }

    /// Remember the outcome of a TLS I/O function.
    /// For OpenSSL, these are functions that need SSL_get_error() follow up.
    void ioError(const int errorNo) { ioErrorNo = errorNo; }

    // TODO: Rename to absorbLibraryErrors().
    /// Extract and remember errors stored internally by the library.
    /// For OpenSSL, these are ERR_get_error()-reported errors.
    void absorbStackedErrors();

    /// extract and remember ERR_get_error()-reported error(s)
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
    virtual SBuf brief() const final;
    virtual SBuf verbose(const HttpRequestPointer &) const final;

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

    Security::ErrorCode error_no;   ///< The error code (XXX)

    /// the earliest error returned by OpenSSL ERR_get_error(3SSL) or zero
    unsigned long lib_error_no = SSL_ERROR_NONE;

    /// TLS I/O operation result returned by OpenSSL SSL_get_error(3SSL) or zero
    int ioErrorNo = 0;

    /// errno(3); system call failure code (or zero)
    int sysErrorNo = 0;

    Security::CertPointer peer_cert; ///< A pointer to the peer certificate
    Security::CertPointer broken_cert; ///< A pointer to the broken certificate (peer or intermediate)
    String errReason; ///< A custom reason for error, else retrieved from OpenSSL.
    mutable ErrorDetailEntry detailEntry;
};

}//namespace Ssl
#endif

