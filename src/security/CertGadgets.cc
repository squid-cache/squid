/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "sbuf/SBuf.h"
#include "security/CertGadgets.h"

#if USE_OPENSSL
#if HAVE_OPENSSL_X509V3_H
#include <openssl/x509v3.h>
#endif
#endif

SBuf
Security::CertIssuerName(const CertPointer &cert)
{
    SBuf out;
#if USE_OPENSSL
    auto s = X509_NAME_oneline(X509_get_issuer_name(cert.get()), nullptr, 0);
    if (!s) {
        const auto x = ERR_get_error();
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer: " << Security::ErrorString(x));
        return out;
    }
    out.append(s);
    OPENSSL_free(s);

#elif USE_GNUTLS
    gnutls_x509_dn_t dn;
    auto x = gnutls_x509_crt_get_issuer(cert.get(), &dn);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer: " << Security::ErrorString(x));
        return out;
    }

    gnutls_datum_t str;
    x = gnutls_x509_dn_get_str(dn, &str);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer: " << Security::ErrorString(x));
        return out;
    }
    out.append(reinterpret_cast<const char *>(str.data), str.size);
    gnutls_free(str.data);

#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate Issuer: [not implemented]");
#endif

    debugs(83, DBG_PARSE_NOTE(3), "found cert issuer=" << out);
    return out;
}

SBuf
Security::CertSubjectName(const CertPointer &cert)
{
    SBuf out;
#if USE_OPENSSL
    auto s = X509_NAME_oneline(X509_get_subject_name(cert.get()), nullptr, 0);
    if (!s) {
        const auto x = ERR_get_error();
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: " << Security::ErrorString(x));
        return out;
    }
    out.append(s);
    OPENSSL_free(s);

#elif USE_GNUTLS
    gnutls_x509_dn_t dn;
    auto x = gnutls_x509_crt_get_subject(cert.get(), &dn);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: " << Security::ErrorString(x));
        return out;
    }

    gnutls_datum_t str;
    x = gnutls_x509_dn_get_str(dn, &str);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: " << Security::ErrorString(x));
        return out;
    }
    out.append(reinterpret_cast<const char *>(str.data), str.size);
    gnutls_free(str.data);

#else
    debugs(83, DBG_PARSE_NOTE(2), "WARNING: cannot get certificate SubjectName: [not implemented]");
#endif

    debugs(83, DBG_PARSE_NOTE(3), "found cert subject=" << out);
    return out;
}

bool
Security::CertIsIssuedBy(const CertPointer &cert, const CertPointer &issuer)
{
#if USE_OPENSSL
    const auto result = X509_check_issued(issuer.get(), cert.get());
    if (result == X509_V_OK)
        return true;
    debugs(83, DBG_PARSE_NOTE(3), CertSubjectName(issuer) << " did not sign " <<
           CertSubjectName(cert) << ": " << VerifyErrorString(result) << " (" << result << ")");
#elif USE_GNUTLS
    const auto result = gnutls_x509_crt_check_issuer(cert.get(), issuer.get());
    if (result == 1)
        return true;
    debugs(83, DBG_PARSE_NOTE(3), CertSubjectName(issuer) << " did not sign " << CertSubjectName(cert));
#else
    // not implemented
#endif
    return false;
}

