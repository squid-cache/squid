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

/**
 * Error details (library and custom squid errors) for access logging and
 * error pages returned to the end user.
 */
class ErrorDetail:  public ::ErrorDetail
{
    MEMPROXY_CLASS(Ssl::ErrorDetail);
public:
    /// Used for server-side TLS certificate verification failures to
    /// detail server certificates and provide extra string describing
    /// the failure.
    /// If the broken certificate is nil then the broken certificate is
    /// the peer certificate.
    ErrorDetail(Security::ErrorCode err_no, X509 *peer, X509 *broken, const char *aReason = NULL);

    /// General TLS handshake failures or failures due to TLS/SSL
    /// library errors
    ErrorDetail(Security::ErrorCode err_no, unsigned long lib_err);
    explicit ErrorDetail(const Security::ErrorCode err_no): error_no(err_no) {}

    /// remember SSL_get_error() result
    void setIoError(const int errorNo) { ioErrorNo = errorNo; }

    /// extract and remember ERR_get_error()-reported error(s)
    void absorbStackedErrors();

    void setSysError(const int xerrno) { sysErrorNo = xerrno; }

    /// The error no
    Security::ErrorCode errorNo() const {return error_no;}
    ///Sets the low-level error returned by OpenSSL ERR_get_error()
    void setLibError(unsigned long lib_err_no) {lib_error_no = lib_err_no;} // XXX: replace with absorbStackedErrors()
    /// the peer certificate
    X509 *peerCert() { return peer_cert.get(); }
    /// peer or intermediate certificate that failed validation
    X509 *brokenCert() {return broken_cert.get(); }

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

