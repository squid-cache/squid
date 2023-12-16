/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/IoManip.h"
#include "error/SysErrorDetail.h"
#include "html/Quoting.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"
#include "security/Certificate.h"
#include "security/ErrorDetail.h"
#include "security/forward.h"
#include "security/Io.h"
#include "util.h"

#if USE_OPENSSL
#include "ssl/ErrorDetailManager.h"
#elif USE_GNUTLS
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#endif
#include <map>
#include <optional>

namespace Security {

// we use std::map to optimize search; TODO: Use std::unordered_map instead?
typedef std::map<ErrorCode, const char *> ErrorCodeNames;
static const ErrorCodeNames TheErrorCodeNames = {
    {   SQUID_TLS_ERR_ACCEPT,
        "SQUID_TLS_ERR_ACCEPT"
    },
    {   SQUID_TLS_ERR_CONNECT,
        "SQUID_TLS_ERR_CONNECT"
    },
    {   SQUID_X509_V_ERR_INFINITE_VALIDATION,
        "SQUID_X509_V_ERR_INFINITE_VALIDATION"
    },
    {   SQUID_X509_V_ERR_CERT_CHANGE,
        "SQUID_X509_V_ERR_CERT_CHANGE"
    },
    {   SQUID_X509_V_ERR_DOMAIN_MISMATCH,
        "SQUID_X509_V_ERR_DOMAIN_MISMATCH"
    },
#if USE_OPENSSL
    {   X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT"
    },
    {   X509_V_ERR_UNABLE_TO_GET_CRL,
        "X509_V_ERR_UNABLE_TO_GET_CRL"
    },
    {   X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
        "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE"
    },
    {   X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
        "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE"
    },
    {   X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
        "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY"
    },
    {   X509_V_ERR_CERT_SIGNATURE_FAILURE,
        "X509_V_ERR_CERT_SIGNATURE_FAILURE"
    },
    {   X509_V_ERR_CRL_SIGNATURE_FAILURE,
        "X509_V_ERR_CRL_SIGNATURE_FAILURE"
    },
    {   X509_V_ERR_CERT_NOT_YET_VALID,
        "X509_V_ERR_CERT_NOT_YET_VALID"
    },
    {   X509_V_ERR_CERT_HAS_EXPIRED,
        "X509_V_ERR_CERT_HAS_EXPIRED"
    },
    {   X509_V_ERR_CRL_NOT_YET_VALID,
        "X509_V_ERR_CRL_NOT_YET_VALID"
    },
    {   X509_V_ERR_CRL_HAS_EXPIRED,
        "X509_V_ERR_CRL_HAS_EXPIRED"
    },
    {   X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
        "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD"
    },
    {   X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
        "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD"
    },
    {   X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
        "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD"
    },
    {   X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
        "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD"
    },
    {   X509_V_ERR_OUT_OF_MEM,
        "X509_V_ERR_OUT_OF_MEM"
    },
    {   X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT"
    },
    {   X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
        "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"
    },
    {   X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
    },
    {   X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
        "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    },
    {   X509_V_ERR_CERT_CHAIN_TOO_LONG,
        "X509_V_ERR_CERT_CHAIN_TOO_LONG"
    },
    {   X509_V_ERR_CERT_REVOKED,
        "X509_V_ERR_CERT_REVOKED"
    },
    {   X509_V_ERR_INVALID_CA,
        "X509_V_ERR_INVALID_CA"
    },
    {   X509_V_ERR_PATH_LENGTH_EXCEEDED,
        "X509_V_ERR_PATH_LENGTH_EXCEEDED"
    },
    {   X509_V_ERR_INVALID_PURPOSE,
        "X509_V_ERR_INVALID_PURPOSE"
    },
    {   X509_V_ERR_CERT_UNTRUSTED,
        "X509_V_ERR_CERT_UNTRUSTED"
    },
    {   X509_V_ERR_CERT_REJECTED,
        "X509_V_ERR_CERT_REJECTED"
    },
    {   X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
        "X509_V_ERR_SUBJECT_ISSUER_MISMATCH"
    },
    {   X509_V_ERR_AKID_SKID_MISMATCH,
        "X509_V_ERR_AKID_SKID_MISMATCH"
    },
    {   X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
        "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH"
    },
    {   X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
        "X509_V_ERR_KEYUSAGE_NO_CERTSIGN"
    },
#if defined(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER)
    {
        X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER, // 33
        "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER"
    },
#endif
#if defined(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
    {
        X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, // 34
        "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN)
    {
        X509_V_ERR_KEYUSAGE_NO_CRL_SIGN, // 35
        "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN"
    },
#endif
#if defined(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION)
    {
        X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION, // 36
        "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_INVALID_NON_CA)
    {
        X509_V_ERR_INVALID_NON_CA, // 37
        "X509_V_ERR_INVALID_NON_CA"
    },
#endif
#if defined(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED)
    {
        X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED, // 38
        "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
    },
#endif
#if defined(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE)
    {
        X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, // 39
        "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE"
    },
#endif
#if defined(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED)
    {
        X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED, // 40
        "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED"
    },
#endif
#if defined(X509_V_ERR_INVALID_EXTENSION)
    {
        X509_V_ERR_INVALID_EXTENSION, // 41
        "X509_V_ERR_INVALID_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_INVALID_POLICY_EXTENSION)
    {
        X509_V_ERR_INVALID_POLICY_EXTENSION, // 42
        "X509_V_ERR_INVALID_POLICY_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_NO_EXPLICIT_POLICY)
    {
        X509_V_ERR_NO_EXPLICIT_POLICY, // 43
        "X509_V_ERR_NO_EXPLICIT_POLICY"
    },
#endif
#if defined(X509_V_ERR_DIFFERENT_CRL_SCOPE)
    {
        X509_V_ERR_DIFFERENT_CRL_SCOPE, // 44
        "X509_V_ERR_DIFFERENT_CRL_SCOPE"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE)
    {
        X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE, // 45
        "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE"
    },
#endif
#if defined(X509_V_ERR_UNNESTED_RESOURCE)
    {
        X509_V_ERR_UNNESTED_RESOURCE, // 46
        "X509_V_ERR_UNNESTED_RESOURCE"
    },
#endif
#if defined(X509_V_ERR_PERMITTED_VIOLATION)
    {
        X509_V_ERR_PERMITTED_VIOLATION, // 47
        "X509_V_ERR_PERMITTED_VIOLATION"
    },
#endif
#if defined(X509_V_ERR_EXCLUDED_VIOLATION)
    {
        X509_V_ERR_EXCLUDED_VIOLATION, // 48
        "X509_V_ERR_EXCLUDED_VIOLATION"
    },
#endif
#if defined(X509_V_ERR_SUBTREE_MINMAX)
    {
        X509_V_ERR_SUBTREE_MINMAX, // 49
        "X509_V_ERR_SUBTREE_MINMAX"
    },
#endif
    {   X509_V_ERR_APPLICATION_VERIFICATION, // 50
        "X509_V_ERR_APPLICATION_VERIFICATION"
    },
#if defined(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE)
    {
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE, // 51
        "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX)
    {
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX, // 52
        "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX)
    {
        X509_V_ERR_UNSUPPORTED_NAME_SYNTAX, // 53
        "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX"
    },
#endif
#if defined(X509_V_ERR_CRL_PATH_VALIDATION_ERROR)
    {
        X509_V_ERR_CRL_PATH_VALIDATION_ERROR, // 54
        "X509_V_ERR_CRL_PATH_VALIDATION_ERROR"
    },
#endif
#if defined(X509_V_ERR_PATH_LOOP)
    {
        X509_V_ERR_PATH_LOOP, // 55
        "X509_V_ERR_PATH_LOOP"
    },
#endif
#if defined(X509_V_ERR_SUITE_B_INVALID_VERSION)
    {
        X509_V_ERR_SUITE_B_INVALID_VERSION, // 56
        "X509_V_ERR_SUITE_B_INVALID_VERSION"
    },
#endif
#if defined(X509_V_ERR_SUITE_B_INVALID_ALGORITHM)
    {
        X509_V_ERR_SUITE_B_INVALID_ALGORITHM, // 57
        "X509_V_ERR_SUITE_B_INVALID_ALGORITHM"
    },
#endif
#if defined(X509_V_ERR_SUITE_B_INVALID_CURVE)
    {
        X509_V_ERR_SUITE_B_INVALID_CURVE, // 58
        "X509_V_ERR_SUITE_B_INVALID_CURVE"
    },
#endif
#if defined(X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM)
    {
        X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM, // 59
        "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM"
    },
#endif
#if defined(X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED)
    {
        X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED, // 60
        "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED"
    },
#endif
#if defined(X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256)
    {
        X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256, // 61
        "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256"
    },
#endif
#if defined(X509_V_ERR_HOSTNAME_MISMATCH)
    {
        X509_V_ERR_HOSTNAME_MISMATCH, // 62
        "X509_V_ERR_HOSTNAME_MISMATCH"
    },
#endif
#if defined(X509_V_ERR_EMAIL_MISMATCH)
    {
        X509_V_ERR_EMAIL_MISMATCH, // 63
        "X509_V_ERR_EMAIL_MISMATCH"
    },
#endif
#if defined(X509_V_ERR_IP_ADDRESS_MISMATCH)
    {
        X509_V_ERR_IP_ADDRESS_MISMATCH, // 64
        "X509_V_ERR_IP_ADDRESS_MISMATCH"
    },
#endif
#if defined(X509_V_ERR_DANE_NO_MATCH)
    {
        X509_V_ERR_DANE_NO_MATCH, // 65
        "X509_V_ERR_DANE_NO_MATCH"
    },
#endif
#if defined(X509_V_ERR_EE_KEY_TOO_SMALL)
    {
        X509_V_ERR_EE_KEY_TOO_SMALL, // 66
        "X509_V_ERR_EE_KEY_TOO_SMALL"
    },
#endif
#if defined(X509_V_ERR_CA_KEY_TOO_SMALL)
    {
        X509_V_ERR_CA_KEY_TOO_SMALL, // 67
        "X509_V_ERR_CA_KEY_TOO_SMALL"
    },
#endif
#if defined(X509_V_ERR_CA_MD_TOO_WEAK)
    {
        X509_V_ERR_CA_MD_TOO_WEAK, // 68
        "X509_V_ERR_CA_MD_TOO_WEAK"
    },
#endif
#if defined(X509_V_ERR_INVALID_CALL)
    {
        X509_V_ERR_INVALID_CALL, // 69
        "X509_V_ERR_INVALID_CALL"
    },
#endif
#if defined(X509_V_ERR_STORE_LOOKUP)
    {
        X509_V_ERR_STORE_LOOKUP, // 70
        "X509_V_ERR_STORE_LOOKUP"
    },
#endif
#if defined(X509_V_ERR_NO_VALID_SCTS)
    {
        X509_V_ERR_NO_VALID_SCTS, // 71
        "X509_V_ERR_NO_VALID_SCTS"
    },
#endif
#if defined(X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION)
    {
        X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION, // 72
        "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION"
    },
#endif
#if defined(X509_V_ERR_OCSP_VERIFY_NEEDED)
    {
        X509_V_ERR_OCSP_VERIFY_NEEDED, // 73
        "X509_V_ERR_OCSP_VERIFY_NEEDED"
    },
#endif
#if defined(X509_V_ERR_OCSP_VERIFY_FAILED)
    {
        X509_V_ERR_OCSP_VERIFY_FAILED, // 74
        "X509_V_ERR_OCSP_VERIFY_FAILED"
    },
#endif
#if defined(X509_V_ERR_OCSP_CERT_UNKNOWN)
    {
        X509_V_ERR_OCSP_CERT_UNKNOWN, // 75
        "X509_V_ERR_OCSP_CERT_UNKNOWN"
    },
#endif
    {
        SSL_ERROR_NONE,
        "SSL_ERROR_NONE"
    },
#endif // USE_OPENSSL
};

} // namespace Security

Security::ErrorCode
Security::ErrorCodeFromName(const char *name)
{
    static auto TheCmp = [](const char *a, const char *b) {return strcmp(a, b) < 0;};
    static std::map<const char *, ErrorCode, decltype(TheCmp)> TheErrorCodeByNameIndx(TheCmp);
    if (TheErrorCodeByNameIndx.empty()) {
        for (const auto &i: TheErrorCodeNames)
            TheErrorCodeByNameIndx.insert(std::make_pair(i.second, i.first));

        // redirector to support legacy error translations
        TheErrorCodeByNameIndx.insert(std::make_pair("SQUID_ERR_SSL_HANDSHAKE", SQUID_TLS_ERR_CONNECT));
    }

    const auto it = TheErrorCodeByNameIndx.find(name);
    if (it != TheErrorCodeByNameIndx.end())
        return it->second;

    return 0;
}

const char *
Security::ErrorNameFromCode(const ErrorCode err, const bool prefixRawCode)
{
    const auto it = TheErrorCodeNames.find(err);
    if (it != TheErrorCodeNames.end())
        return it->second;

    static char tmpBuffer[128];
    snprintf(tmpBuffer, sizeof(tmpBuffer), "%s%d",
             (prefixRawCode ? "SSL_ERR=" : ""), static_cast<int>(err));
    return tmpBuffer;
}

/* Security::ErrorDetail */

/// helper constructor implementing the logic shared by the two public ones
Security::ErrorDetail::ErrorDetail(const ErrorCode err, const int aSysErrorNo):
    error_no(err),
    // We could restrict errno(3) collection to cases where the TLS library
    // explicitly talks about the errno being set, but correctly detecting those
    // cases is difficult. We simplify in hope that all other cases will either
    // have a useful errno or a zero errno.
    sysErrorNo(aSysErrorNo)
{
#if USE_OPENSSL
    /// Extract and remember errors stored internally by the TLS library.
    if ((lib_error_no = ERR_get_error())) {
        debugs(83, 7, "got 0x" << asHex(lib_error_no));
        // more errors may be stacked
        // TODO: Save/detail all stacked errors by always flushing stale ones.
        ForgetErrors();
    }
#else
    // other libraries return errors explicitly instead of auto-storing them
#endif
}

Security::ErrorDetail::ErrorDetail(const ErrorCode anErrorCode, const CertPointer &cert, const CertPointer &broken, const char *aReason):
    ErrorDetail(anErrorCode, 0)
{
    errReason = aReason;
    peer_cert = cert;
    broken_cert = broken ? broken : cert;
}

#if USE_OPENSSL
Security::ErrorDetail::ErrorDetail(const ErrorCode anErrorCode, const int anIoErrorNo, const int aSysErrorNo):
    ErrorDetail(anErrorCode, aSysErrorNo)
{
    ioErrorNo = anIoErrorNo;
}

#elif USE_GNUTLS
Security::ErrorDetail::ErrorDetail(const ErrorCode anErrorCode, const LibErrorCode aLibErrorNo, const int aSysErrorNo):
    ErrorDetail(anErrorCode, aSysErrorNo)
{
    lib_error_no = aLibErrorNo;
}
#endif

void
Security::ErrorDetail::setPeerCertificate(const CertPointer &cert)
{
    assert(cert);
    assert(!peer_cert);
    assert(!broken_cert);
    peer_cert = cert;
    // unlike the constructor, the supplied certificate is not a broken_cert
}

SBuf
Security::ErrorDetail::brief() const
{
    SBufStream os;

    printErrorCode(os);

    if (lib_error_no) {
#if USE_OPENSSL
        // TODO: Log ERR_error_string_n() instead, despite length, whitespace?
        // Example: `error:1408F09C:SSL routines:ssl3_get_record:http request`.
        os << "+TLS_LIB_ERR=" << asHex(lib_error_no).upperCase();
#elif USE_GNUTLS
        os << '+' << gnutls_strerror_name(lib_error_no);
#endif
    }

#if USE_OPENSSL
    // TODO: Consider logging long but human-friendly names (e.g.,
    // SSL_ERROR_SYSCALL).
    if (ioErrorNo)
        os << "+TLS_IO_ERR=" << ioErrorNo;
#endif

    if (sysErrorNo) {
        os << '+' << SysErrorDetail::Brief(sysErrorNo);
    }

    if (broken_cert)
        os << "+broken_cert";

    return os.buf();
}

SBuf
Security::ErrorDetail::verbose(const HttpRequestPointer &request) const
{
    std::optional<SBuf> customFormat;
#if USE_OPENSSL
    if (const auto errorDetail = Ssl::ErrorDetailsManager::GetInstance().findDetail(error_no, request))
        customFormat = errorDetail->detail;
#else
    (void)request;
#endif
    auto format = customFormat ? customFormat->c_str() : "SSL handshake error (%err_name)";

    SBufStream os;
    assert(format);
    auto remainder = format;
    while (auto p = strchr(remainder, '%')) {
        os.write(remainder, p - remainder);
        const auto formattingCodeLen = convertErrorCodeToDescription(++p, os);
        if (!formattingCodeLen)
            os << '%';
        remainder = p + formattingCodeLen;
    }
    os << remainder;
    return os.buf();
}

/// textual representation of the subject of the broken certificate
void
Security::ErrorDetail::printSubject(std::ostream &os) const
{
    if (broken_cert) {
        auto buf = SubjectName(*broken_cert);
        if (!buf.isEmpty()) {
            // TODO: Convert html_quote() into an std::ostream manipulator.
            // quote to avoid possible html code injection through
            // certificate subject
            os << html_quote(buf.c_str());
            return;
        }
    }
    os << "[Not available]";
}

#if USE_OPENSSL
/// a helper class to print CNs extracted using Ssl::matchX509CommonNames()
class CommonNamesPrinter
{
public:
    explicit CommonNamesPrinter(std::ostream &os): os_(os) {}

    /// Ssl::matchX509CommonNames() visitor that reports the given name (if any)
    static int PrintName(void *, ASN1_STRING *);

    /// whether any names have been printed so far
    bool printed = false;

private:
    void printName(const ASN1_STRING *);

    std::ostream &os_; ///< destination for printed names
};

int
CommonNamesPrinter::PrintName(void * const printer, ASN1_STRING * const name)
{
    assert(printer);
    static_cast<CommonNamesPrinter*>(printer)->printName(name);
    return 1;
}

/// prints an HTML-quoted version of the given common name (as a part of the
/// printed names list)
void
CommonNamesPrinter::printName(const ASN1_STRING * const name)
{
    if (name && name->length) {
        if (printed)
            os_ << ", ";

        // TODO: Convert html_quote() into an std::ostream manipulator accepting (buf, n).
        SBuf buf(reinterpret_cast<const char *>(name->data), name->length);
        os_ << html_quote(buf.c_str());

        printed = true;
    }
}
#endif // USE_OPENSSL

/// a list of the broken certificates CN and alternate names
void
Security::ErrorDetail::printCommonName(std::ostream &os) const
{
#if USE_OPENSSL
    if (broken_cert.get()) {
        CommonNamesPrinter printer(os);
        Ssl::matchX509CommonNames(broken_cert.get(), &printer, printer.PrintName);
        if (printer.printed)
            return;
    }
#endif // USE_OPENSSL
    os << "[Not available]";
}

/// the issuer of the broken certificate
void
Security::ErrorDetail::printCaName(std::ostream &os) const
{
    if (broken_cert) {
        auto buf = IssuerName(*broken_cert);
        if (!buf.isEmpty()) {
            // quote to avoid possible html code injection through
            // certificate issuer subject
            os << html_quote(buf.c_str());
            return;
        }
    }
    os << "[Not available]";
}

/// textual representation of the "not before" field of the broken certificate
void
Security::ErrorDetail::printNotBefore(std::ostream &os) const
{
#if USE_OPENSSL
    if (broken_cert.get()) {
        if (const auto tm = X509_getm_notBefore(broken_cert.get())) {
            // TODO: Add and use an ASN1_TIME printing operator instead.
            static char tmpBuffer[256]; // A temporary buffer
            Ssl::asn1timeToString(tm, tmpBuffer, sizeof(tmpBuffer));
            os << tmpBuffer;
            return;
        }
    }
#endif // USE_OPENSSL
    os << "[Not available]";
}

/// textual representation of the "not after" field of the broken certificate
void
Security::ErrorDetail::printNotAfter(std::ostream &os) const
{
#if USE_OPENSSL
    if (broken_cert.get()) {
        if (const auto tm = X509_getm_notAfter(broken_cert.get())) {
            // XXX: Reduce code duplication.
            static char tmpBuffer[256]; // A temporary buffer
            Ssl::asn1timeToString(tm, tmpBuffer, sizeof(tmpBuffer));
            os << tmpBuffer;
            return;
        }
    }
#endif // USE_OPENSSL
    os << "[Not available]";
}

/// textual representation of error_no
void
Security::ErrorDetail::printErrorCode(std::ostream &os) const
{
#if USE_OPENSSL
    // try detailEntry first because it is faster
    if (detailEntry) {
        os << detailEntry->name;
        return;
    }
#endif
    os << ErrorNameFromCode(error_no);
}

/// short description of error_no
void
Security::ErrorDetail::printErrorDescription(std::ostream &os) const
{
    if (!error_no) {
        os << "[No Error]";
        return;
    }

#if USE_OPENSSL
    if (detailEntry) {
        os << detailEntry->descr;
        return;
    }
#endif

    os << "[Not available]";
}

/// textual representation of lib_error_no
void
Security::ErrorDetail::printErrorLibError(std::ostream &os) const
{
    if (errReason.size() > 0)
        os << errReason;
    else if (lib_error_no)
        os << ErrorString(lib_error_no);
    else
        os << "[No Error]";
}

/**
 * Converts the code to a string value. Supported formatting codes are:
 *
 * Error meta information:
 * %err_name: The name of a high-level SSL error (e.g., X509_V_ERR_*)
 * %ssl_error_descr: A short description of the SSL error
 * %ssl_lib_error: human-readable low-level error string by ErrorString()
 *
 * Certificate information extracted from broken (not necessarily peer!) cert
 * %ssl_cn: The comma-separated list of common and alternate names
 * %ssl_subject: The certificate subject
 * %ssl_ca_name: The certificate issuer name
 * %ssl_notbefore: The certificate "not before" field
 * %ssl_notafter: The certificate "not after" field
 *
 \returns the length of the code (the number of characters to be replaced by value)
 \retval 0 for unsupported codes
*/
size_t
Security::ErrorDetail::convertErrorCodeToDescription(const char * const code, std::ostream &os) const
{
    using PartDescriber = void (ErrorDetail::*)(std::ostream &os) const;
    static const std::map<const char*, PartDescriber> PartDescriberByCode = {
        {"ssl_subject", &ErrorDetail::printSubject},
        {"ssl_ca_name", &ErrorDetail::printCaName},
        {"ssl_cn", &ErrorDetail::printCommonName},
        {"ssl_notbefore", &ErrorDetail::printNotBefore},
        {"ssl_notafter", &ErrorDetail::printNotAfter},
        {"err_name", &ErrorDetail::printErrorCode},
        {"ssl_error_descr", &ErrorDetail::printErrorDescription},
        {"ssl_lib_error", &ErrorDetail::printErrorLibError}
    };

    // We can refactor the map to find matches without looping, but that
    // requires a "starts with" comparison function -- `code` length is unknown.
    for (const auto &pair: PartDescriberByCode) {
        const auto len = strlen(pair.first);
        if (strncmp(code, pair.first, len) == 0) {
            const auto method = pair.second;
            (this->*method)(os);
            return len;
        }
    }

    // TODO: Support logformat %codes.
    return 0;
}

