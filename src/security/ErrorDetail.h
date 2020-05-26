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
#include "security/forward.h"
#if USE_OPENSSL
#include "ssl/ErrorDetail.h"
#endif

/// Squid-specific TLS handling errors (a subset of ErrorCode)
/// These errors either distinguish high-level library calls/contexts or
/// supplement official certificate validation errors to cover special cases.
/// We use negative values, assuming that those official errors are positive.
enum {
    SQUID_TLS_ERR_OFFSET = INT_MIN,

    /* TLS library calls/contexts other than validation (e.g., I/O) */
    SQUID_TLS_ERR_ACCEPT, ///< failure to accept a connection from a TLS client
    SQUID_TLS_ERR_CONNECT, ///< failure to establish a connection with a TLS server

    /* certificate validation problems not covered by official errors */
    SQUID_X509_V_ERR_CERT_CHANGE,
    SQUID_X509_V_ERR_DOMAIN_MISMATCH,
    SQUID_X509_V_ERR_INFINITE_VALIDATION,

    SQUID_TLS_ERR_END
};

namespace Security {

#if USE_OPENSSL

typedef RefCount<Ssl::ErrorDetail> ErrorDetailPointer;

#elif USE_GNUTLS

class ErrorDetail: public ::ErrorDetail
{
    MEMPROXY_CLASS(Security::ErrorDetail);

public:
    typedef RefCount<ErrorDetail> Pointer;

    /// Details (or starts detailing) a non-validation failure.
    /// \param anErrorNo an error reported by the TLS library.
    ErrorDetail(int anErrorCode, int anErrorNo) : error_no(anErrorCode), libErrorNo(anErrorNo) {}


    virtual SBuf brief() const;
    virtual SBuf verbose(const HttpRequestPointer &) const;

    /// error category; \see Security::ErrorCode
    Security::ErrorCode error_no = 0;

    /// The error reported by GnuTLS library
    int libErrorNo = 0;
};

typedef RefCount<ErrorDetail> ErrorDetailPointer;

#else

typedef RefCount<void> ErrorDetailPointer;

#endif

}

#endif
