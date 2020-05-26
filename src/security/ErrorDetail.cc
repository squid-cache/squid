/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/SBuf.h"
#include "security/ErrorDetail.h"
#include "security/forward.h"
#include "util.h"

#if USE_GNUTLS
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#endif
#include <map>

#if USE_OPENSSL
// configure defines both USE_GNUTLS and USE_OPENSSL
#elif USE_GNUTLS

namespace Security {
    typedef std::map<Security::ErrorCode, SBuf> SquidTlsErrorsMap;
static SquidTlsErrorsMap SquidTlsErrorsByErrNo {
    {SQUID_TLS_ERR_ACCEPT,  SBuf("SQUID_TLS_ERR_ACCEPT") },
    {SQUID_TLS_ERR_CONNECT, SBuf("SQUID_TLS_ERR_CONNECT")},
    {SQUID_X509_V_ERR_INFINITE_VALIDATION, SBuf("SQUID_X509_V_ERR_INFINITE_VALIDATION")},
    {SQUID_X509_V_ERR_CERT_CHANGE, SBuf("SQUID_X509_V_ERR_CERT_CHANGE")},
    {SQUID_X509_V_ERR_DOMAIN_MISMATCH, SBuf("SQUID_X509_V_ERR_DOMAIN_MISMATCH")}
};

static SBuf GetTlsErrorName(int err);
}

SBuf Security::GetTlsErrorName(int err)
{
    auto it = SquidTlsErrorsByErrNo.find(err);
    if (it != SquidTlsErrorsByErrNo.end()) {
        return it->second;
    }
    return SBuf("Unknown");
}

SBuf Security::ErrorDetail::brief() const
{
    // Prepend the string of error_no
    SBuf buf(Security::GetTlsErrorName(error_no));
    buf.append("+TLS_IO_ERR=");
    buf.append(gnutls_strerror_name(libErrorNo));
    return buf;
}

SBuf Security::ErrorDetail::verbose(const HttpRequestPointer &) const
{
    // Prepend the string of error_no
    SBuf buf(Security::GetTlsErrorName(error_no));
    buf.append(":");
    buf.append(gnutls_strerror (libErrorNo));
    return buf;
}

#endif
