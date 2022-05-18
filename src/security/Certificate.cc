/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "debug/Stream.h"
#include "sbuf/SBuf.h"
#include "security/Certificate.h"

#if USE_OPENSSL
#include "ssl/gadgets.h"
#endif

#include <iostream>

inline
const char *
MissingLibraryError()
{
    return "[need OpenSSL or GnuTLS]";
}

SBuf
Security::IssuerName(Certificate &cert)
{
    SBuf out;

#if USE_OPENSSL
    Ssl::ForgetErrors();
    const auto s = X509_NAME_oneline(X509_get_issuer_name(&cert), nullptr, 0);
    if (!s) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer:" << Ssl::ReportAndForgetErrors);
        return out;
    }
    out.append(s);
    OPENSSL_free(s);

#elif USE_GNUTLS
    gnutls_x509_dn_t dn;
    auto x = gnutls_x509_crt_get_issuer(&cert, &dn);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer: " << ErrorString(x));
        return out;
    }

    gnutls_datum_t str;
    x = gnutls_x509_dn_get_str(dn, &str);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot describe certificate Issuer: " << ErrorString(x));
        return out;
    }
    out.append(reinterpret_cast<const char *>(str.data), str.size);
    gnutls_free(str.data);

#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer: " << MissingLibraryError());
#endif

    return out;
}

SBuf
Security::SubjectName(Certificate &cert)
{
    SBuf out;

#if USE_OPENSSL
    Ssl::ForgetErrors();
    auto s = X509_NAME_oneline(X509_get_subject_name(&cert), nullptr, 0);
    if (!s) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName" << Ssl::ReportAndForgetErrors);
        return out;
    }
    out.append(s);
    OPENSSL_free(s);

#elif USE_GNUTLS
    gnutls_x509_dn_t dn;
    auto x = gnutls_x509_crt_get_subject(&cert, &dn);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: " << ErrorString(x));
        return out;
    }

    gnutls_datum_t str;
    x = gnutls_x509_dn_get_str(dn, &str);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot describe certificate SubjectName: " << ErrorString(x));
        return out;
    }
    out.append(reinterpret_cast<const char *>(str.data), str.size);
    gnutls_free(str.data);

#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: " << MissingLibraryError());
#endif

    return out;
}

bool
Security::IsIssuedBy(Certificate &cert, Certificate &issuer)
{
#if USE_OPENSSL
    Ssl::ForgetErrors();
    const auto result = X509_check_issued(&issuer, &cert);
    if (result == X509_V_OK)
        return true;
    debugs(83, DBG_PARSE_NOTE(3), issuer << " did not sign " << cert << ":" <<
           Debug::Extra << "X509_check_issued() result: " << X509_verify_cert_error_string(result) << " (" << result << ")" <<
           Ssl::ReportAndForgetErrors);
#elif USE_GNUTLS
    const auto result = gnutls_x509_crt_check_issuer(&cert, &issuer);
    if (result == 1)
        return true;
    debugs(83, DBG_PARSE_NOTE(3), issuer << " did not sign " << cert);
#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot determine certificates relationship: " << MissingLibraryError());
#endif
    return false;
}

std::ostream &
operator <<(std::ostream &os, Security::Certificate &cert)
{
    // TODO: Optimize by avoiding memory allocation for this written temporary
    const auto name = Security::SubjectName(cert);
    if (name.isEmpty())
        os << "[no subject name]";
    else
        os << name;
    return os;
}

