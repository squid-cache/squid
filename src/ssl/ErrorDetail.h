/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SSL_ERROR_DETAIL_H
#define _SQUID_SSL_ERROR_DETAIL_H

#include "err_detail_type.h"
#include "ErrorDetailManager.h"
#include "HttpRequest.h"
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

/// The string representation of the TLS error "value"
const char *GetErrorName(Security::ErrorCode value);

/// A short description of the TLS error "value"
const char *GetErrorDescr(Security::ErrorCode value);

/// \return true if the TLS error is optional and may not be supported by current squid version
bool ErrorIsOptional(const char *name);

/**
 * Used to pass SSL error details to the error pages returned to the
 * end user.
 */
class ErrorDetail
{
public:
    // if broken certificate is nil, the peer certificate is broken
    ErrorDetail(Security::ErrorCode err_no, X509 *peer, X509 *broken, const char *aReason = NULL);
    ErrorDetail(ErrorDetail const &);
    const String &toString() const;  ///< An error detail string to embed in squid error pages
    void useRequest(HttpRequest *aRequest) { if (aRequest != NULL) request = aRequest;}
    /// The error name to embed in squid error pages
    const char *errorName() const {return err_code();}
    /// The error no
    Security::ErrorCode errorNo() const {return error_no;}
    ///Sets the low-level error returned by OpenSSL ERR_get_error()
    void setLibError(unsigned long lib_err_no) {lib_error_no = lib_err_no;}
    /// the peer certificate
    X509 *peerCert() { return peer_cert.get(); }
    /// peer or intermediate certificate that failed validation
    X509 *brokenCert() {return broken_cert.get(); }
private:
    typedef const char * (ErrorDetail::*fmt_action_t)() const;
    /**
     * Holds a formating code and its conversion method
     */
    class err_frm_code
    {
    public:
        const char *code;             ///< The formating code
        fmt_action_t fmt_action; ///< A pointer to the conversion method
    };
    static err_frm_code  ErrorFormatingCodes[]; ///< The supported formating codes

    const char *subject() const;
    const char *ca_name() const;
    const char *cn() const;
    const char *notbefore() const;
    const char *notafter() const;
    const char *err_code() const;
    const char *err_descr() const;
    const char *err_lib_error() const;

    int convert(const char *code, const char **value) const;
    void buildDetail() const;

    mutable String errDetailStr; ///< Caches the error detail message
    Security::ErrorCode error_no;   ///< The error code
    unsigned long lib_error_no; ///< low-level error returned by OpenSSL ERR_get_error(3SSL)
    Security::CertPointer peer_cert; ///< A pointer to the peer certificate
    Security::CertPointer broken_cert; ///< A pointer to the broken certificate (peer or intermediate)
    String errReason; ///< A custom reason for error, else retrieved from OpenSSL.
    mutable ErrorDetailEntry detailEntry;
    HttpRequest::Pointer request;
};

}//namespace Ssl
#endif

