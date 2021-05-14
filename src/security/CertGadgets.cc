/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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
Security::CertSubjectName(const Security::CertPointer &cert)
{
    SBuf out;
#if USE_OPENSSL
    auto s = X509_NAME_oneline(X509_get_subject_name(cert.get()), nullptr, 0);
    if (!s) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "WARNING: X509_get_subject_name: " << Security::ErrorString(x));
        return out;
    }
    out.append(s);
    OPENSSL_free(s);

#elif USE_GNUTLS
    gnutls_x509_dn_t dn;
    auto x = gnutls_x509_crt_get_subject(cert.get(), &dn);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "WARNING: gnutls_x509_crt_get_subject: " << Security::ErrorString(x));
        return out;
    }

    gnutls_datum_t str;
    x = gnutls_x509_dn_get_str(dn, &str);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "WARNING: gnutls_x509_dn_get_str: " << Security::ErrorString(x));
        return out;
    }
    out.append(reinterpret_cast<const char *>(str.data), str.size);
    gnutls_free(str.data);

#else
    // fail
    out.append("[not implemented]");
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
    debugs(83, DBG_PARSE_NOTE(3), CertSubjectName(issuer) << " did not sign "
           CertSubjectName(cert) << ": " << VerifyErrorString(result) << " (" << result << ")");
    return false;
#elif USE_GNUTLS
    // GnuTLS does not detail negative answers so no debugs()
    return gnutls_x509_crt_check_issuer(cert.get(), issuer.get()) == 1;
#else
    return false; // not implemented
#endif
}
