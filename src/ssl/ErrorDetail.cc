/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "errorpage.h"
#include "fatal.h"
#include "html_quote.h"
#include "ssl/ErrorDetail.h"

#include <climits>
#include <map>

struct SslErrorEntry {
    Security::ErrorCode value;
    const char *name;
};

static const char *SslErrorDetailDefaultStr = "SSL handshake error (%err_name)";
//Use std::map to optimize search
typedef std::map<Security::ErrorCode, const SslErrorEntry *> SslErrors;
SslErrors TheSslErrors;

static SslErrorEntry TheSslErrorArray[] = {
    {   SQUID_X509_V_ERR_INFINITE_VALIDATION,
        "SQUID_X509_V_ERR_INFINITE_VALIDATION"
    },
    {   SQUID_X509_V_ERR_CERT_CHANGE,
        "SQUID_X509_V_ERR_CERT_CHANGE"
    },
    {   SQUID_ERR_SSL_HANDSHAKE,
        "SQUID_ERR_SSL_HANDSHAKE"
    },
    {   SQUID_X509_V_ERR_DOMAIN_MISMATCH,
        "SQUID_X509_V_ERR_DOMAIN_MISMATCH"
    },
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
        X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER, //33
        "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER"
    },
#endif
#if defined(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
    {
        X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, //34
        "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN)
    {
        X509_V_ERR_KEYUSAGE_NO_CRL_SIGN, //35
        "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN"
    },
#endif
#if defined(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION)
    {
        X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION, //36
        "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_INVALID_NON_CA)
    {
        X509_V_ERR_INVALID_NON_CA, //37
        "X509_V_ERR_INVALID_NON_CA"
    },
#endif
#if defined(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED)
    {
        X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED, //38
        "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
    },
#endif
#if defined(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE)
    {
        X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, //39
        "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE"
    },
#endif
#if defined(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED)
    {
        X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED, //40
        "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED"
    },
#endif
#if defined(X509_V_ERR_INVALID_EXTENSION)
    {
        X509_V_ERR_INVALID_EXTENSION, //41
        "X509_V_ERR_INVALID_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_INVALID_POLICY_EXTENSION)
    {
        X509_V_ERR_INVALID_POLICY_EXTENSION, //42
        "X509_V_ERR_INVALID_POLICY_EXTENSION"
    },
#endif
#if defined(X509_V_ERR_NO_EXPLICIT_POLICY)
    {
        X509_V_ERR_NO_EXPLICIT_POLICY, //43
        "X509_V_ERR_NO_EXPLICIT_POLICY"
    },
#endif
#if defined(X509_V_ERR_DIFFERENT_CRL_SCOPE)
    {
        X509_V_ERR_DIFFERENT_CRL_SCOPE, //44
        "X509_V_ERR_DIFFERENT_CRL_SCOPE"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE)
    {
        X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE, //45
        "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE"
    },
#endif
#if defined(X509_V_ERR_UNNESTED_RESOURCE)
    {
        X509_V_ERR_UNNESTED_RESOURCE, //46
        "X509_V_ERR_UNNESTED_RESOURCE"
    },
#endif
#if defined(X509_V_ERR_PERMITTED_VIOLATION)
    {
        X509_V_ERR_PERMITTED_VIOLATION, //47
        "X509_V_ERR_PERMITTED_VIOLATION"
    },
#endif
#if defined(X509_V_ERR_EXCLUDED_VIOLATION)
    {
        X509_V_ERR_EXCLUDED_VIOLATION, //48
        "X509_V_ERR_EXCLUDED_VIOLATION"
    },
#endif
#if defined(X509_V_ERR_SUBTREE_MINMAX)
    {
        X509_V_ERR_SUBTREE_MINMAX, //49
        "X509_V_ERR_SUBTREE_MINMAX"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE)
    {
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE, //51
        "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX)
    {
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX, //52
        "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX"
    },
#endif
#if defined(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX)
    {
        X509_V_ERR_UNSUPPORTED_NAME_SYNTAX, //53
        "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX"
    },
#endif
#if defined(X509_V_ERR_CRL_PATH_VALIDATION_ERROR)
    {
        X509_V_ERR_CRL_PATH_VALIDATION_ERROR, //54
        "X509_V_ERR_CRL_PATH_VALIDATION_ERROR"
    },
#endif
    {   X509_V_ERR_APPLICATION_VERIFICATION,
        "X509_V_ERR_APPLICATION_VERIFICATION"
    },
    { SSL_ERROR_NONE, "SSL_ERROR_NONE"},
    {SSL_ERROR_NONE, NULL}
};

static const char *OptionalSslErrors[] = {
    "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER",
    "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION",
    "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN",
    "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION",
    "X509_V_ERR_INVALID_NON_CA",
    "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED",
    "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE",
    "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED",
    "X509_V_ERR_INVALID_EXTENSION",
    "X509_V_ERR_INVALID_POLICY_EXTENSION",
    "X509_V_ERR_NO_EXPLICIT_POLICY",
    "X509_V_ERR_DIFFERENT_CRL_SCOPE",
    "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE",
    "X509_V_ERR_UNNESTED_RESOURCE",
    "X509_V_ERR_PERMITTED_VIOLATION",
    "X509_V_ERR_EXCLUDED_VIOLATION",
    "X509_V_ERR_SUBTREE_MINMAX",
    "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE",
    "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX",
    "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX",
    "X509_V_ERR_CRL_PATH_VALIDATION_ERROR",
    NULL
};

struct SslErrorAlias {
    const char *name;
    const Security::ErrorCode *errors;
};

static const Security::ErrorCode hasExpired[] = {X509_V_ERR_CERT_HAS_EXPIRED, SSL_ERROR_NONE};
static const Security::ErrorCode notYetValid[] = {X509_V_ERR_CERT_NOT_YET_VALID, SSL_ERROR_NONE};
static const Security::ErrorCode domainMismatch[] = {SQUID_X509_V_ERR_DOMAIN_MISMATCH, SSL_ERROR_NONE};
static const Security::ErrorCode certUntrusted[] = {X509_V_ERR_INVALID_CA,
                                                    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
                                                    X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
                                                    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
                                                    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                                                    X509_V_ERR_CERT_UNTRUSTED, SSL_ERROR_NONE
                                                   };
static const Security::ErrorCode certSelfSigned[] = {X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, SSL_ERROR_NONE};

// The list of error name shortcuts  for use with ssl_error acls.
// The keys without the "ssl::" scope prefix allow shorter error
// names within the SSL options scope. This is easier than
// carefully stripping the scope prefix in Ssl::ParseErrorString().
static SslErrorAlias TheSslErrorShortcutsArray[] = {
    {"ssl::certHasExpired", hasExpired},
    {"certHasExpired", hasExpired},
    {"ssl::certNotYetValid", notYetValid},
    {"certNotYetValid", notYetValid},
    {"ssl::certDomainMismatch", domainMismatch},
    {"certDomainMismatch", domainMismatch},
    {"ssl::certUntrusted", certUntrusted},
    {"certUntrusted", certUntrusted},
    {"ssl::certSelfSigned", certSelfSigned},
    {"certSelfSigned", certSelfSigned},
    {NULL, NULL}
};

// Use std::map to optimize search.
typedef std::map<std::string, const Security::ErrorCode *> SslErrorShortcuts;
SslErrorShortcuts TheSslErrorShortcuts;

static void loadSslErrorMap()
{
    assert(TheSslErrors.empty());
    for (int i = 0; TheSslErrorArray[i].name; ++i) {
        TheSslErrors[TheSslErrorArray[i].value] = &TheSslErrorArray[i];
    }
}

static void loadSslErrorShortcutsMap()
{
    assert(TheSslErrorShortcuts.empty());
    for (int i = 0; TheSslErrorShortcutsArray[i].name; ++i)
        TheSslErrorShortcuts[TheSslErrorShortcutsArray[i].name] = TheSslErrorShortcutsArray[i].errors;
}

Security::ErrorCode Ssl::GetErrorCode(const char *name)
{
    //TODO: use a std::map?
    for (int i = 0; TheSslErrorArray[i].name != NULL; ++i) {
        if (strcmp(name, TheSslErrorArray[i].name) == 0)
            return TheSslErrorArray[i].value;
    }
    return SSL_ERROR_NONE;
}

bool
Ssl::ParseErrorString(const char *name, Security::Errors &errors)
{
    assert(name);

    const Security::ErrorCode ssl_error = GetErrorCode(name);
    if (ssl_error != SSL_ERROR_NONE) {
        errors.emplace(ssl_error);
        return true;
    }

    if (xisdigit(*name)) {
        const long int value = strtol(name, NULL, 0);
        if (SQUID_SSL_ERROR_MIN <= value && value <= SQUID_SSL_ERROR_MAX) {
            errors.emplace(value);
            return true;
        }
        fatalf("Too small or too big TLS error code '%s'", name);
    }

    if (TheSslErrorShortcuts.empty())
        loadSslErrorShortcutsMap();

    const SslErrorShortcuts::const_iterator it = TheSslErrorShortcuts.find(name);
    if (it != TheSslErrorShortcuts.end()) {
        // Should not be empty...
        assert(it->second[0] != SSL_ERROR_NONE);
        for (int i = 0; it->second[i] != SSL_ERROR_NONE; ++i) {
            errors.emplace(it->second[i]);
        }
        return true;
    }

    fatalf("Unknown TLS error name '%s'", name);
    return false; // not reached
}

const char *Ssl::GetErrorName(Security::ErrorCode value)
{
    if (TheSslErrors.empty())
        loadSslErrorMap();

    const SslErrors::const_iterator it = TheSslErrors.find(value);
    if (it != TheSslErrors.end())
        return it->second->name;

    return NULL;
}

bool
Ssl::ErrorIsOptional(const char *name)
{
    for (int i = 0; OptionalSslErrors[i] != NULL; ++i) {
        if (strcmp(name, OptionalSslErrors[i]) == 0)
            return true;
    }
    return false;
}

const char *
Ssl::GetErrorDescr(Security::ErrorCode value)
{
    return ErrorDetailsManager::GetInstance().getDefaultErrorDescr(value);
}

Ssl::ErrorDetail::err_frm_code Ssl::ErrorDetail::ErrorFormatingCodes[] = {
    {"ssl_subject", &Ssl::ErrorDetail::subject},
    {"ssl_ca_name", &Ssl::ErrorDetail::ca_name},
    {"ssl_cn", &Ssl::ErrorDetail::cn},
    {"ssl_notbefore", &Ssl::ErrorDetail::notbefore},
    {"ssl_notafter", &Ssl::ErrorDetail::notafter},
    {"err_name", &Ssl::ErrorDetail::err_code},
    {"ssl_error_descr", &Ssl::ErrorDetail::err_descr},
    {"ssl_lib_error", &Ssl::ErrorDetail::err_lib_error},
    {NULL,NULL}
};

/**
 * The subject of the current certification in text form
 */
const char  *Ssl::ErrorDetail::subject() const
{
    if (broken_cert.get()) {
        static char tmpBuffer[256]; // A temporary buffer
        if (X509_NAME_oneline(X509_get_subject_name(broken_cert.get()), tmpBuffer, sizeof(tmpBuffer))) {
            // quote to avoid possible html code injection through
            // certificate subject
            return html_quote(tmpBuffer);
        }
    }
    return "[Not available]";
}

// helper function to be used with Ssl::matchX509CommonNames
static int copy_cn(void *check_data,  ASN1_STRING *cn_data)
{
    String *str = (String *)check_data;
    if (!str) // no data? abort
        return 0;
    if (cn_data && cn_data->length) {
        if (str->size() > 0)
            str->append(", ");
        str->append((const char *)cn_data->data, cn_data->length);
    }
    return 1;
}

/**
 * The list with certificates cn and alternate names
 */
const char *Ssl::ErrorDetail::cn() const
{
    if (broken_cert.get()) {
        static String tmpStr;  ///< A temporary string buffer
        tmpStr.clean();
        Ssl::matchX509CommonNames(broken_cert.get(), &tmpStr, copy_cn);
        if (tmpStr.size()) {
            // quote to avoid possible html code injection through
            // certificate subject
            return html_quote(tmpStr.termedBuf());
        }
    }
    return "[Not available]";
}

/**
 * The issuer name
 */
const char *Ssl::ErrorDetail::ca_name() const
{
    if (broken_cert.get()) {
        static char tmpBuffer[256]; // A temporary buffer
        if (X509_NAME_oneline(X509_get_issuer_name(broken_cert.get()), tmpBuffer, sizeof(tmpBuffer))) {
            // quote to avoid possible html code injection through
            // certificate issuer subject
            return html_quote(tmpBuffer);
        }
    }
    return "[Not available]";
}

/**
 * The certificate "not before" field
 */
const char *Ssl::ErrorDetail::notbefore() const
{
    if (broken_cert.get()) {
        if (const auto tm = X509_getm_notBefore(broken_cert.get())) {
            static char tmpBuffer[256]; // A temporary buffer
            Ssl::asn1timeToString(tm, tmpBuffer, sizeof(tmpBuffer));
            return tmpBuffer;
        }
    }
    return "[Not available]";
}

/**
 * The certificate "not after" field
 */
const char *Ssl::ErrorDetail::notafter() const
{
    if (broken_cert.get()) {
        if (const auto tm = X509_getm_notAfter(broken_cert.get())) {
            static char tmpBuffer[256]; // A temporary buffer
            Ssl::asn1timeToString(tm, tmpBuffer, sizeof(tmpBuffer));
            return tmpBuffer;
        }
    }
    return "[Not available]";
}

/**
 * The string representation of the error_no
 */
const char *Ssl::ErrorDetail::err_code() const
{
    static char tmpBuffer[64];
    // We can use the GetErrorName but using the detailEntry is faster,
    // so try it first.
    const char *err = detailEntry.name.termedBuf();

    // error details not loaded yet or not defined in error_details.txt,
    // try the GetErrorName...
    if (!err)
        err = GetErrorName(error_no);

    if (!err) {
        snprintf(tmpBuffer, 64, "%d", (int)error_no);
        err = tmpBuffer;
    }
    return err;
}

/**
 * A short description of the error_no
 */
const char *Ssl::ErrorDetail::err_descr() const
{
    if (error_no == SSL_ERROR_NONE)
        return "[No Error]";
    if (const char *err = detailEntry.descr.termedBuf())
        return err;
    return "[Not available]";
}

const char *Ssl::ErrorDetail::err_lib_error() const
{
    if (errReason.size() > 0)
        return errReason.termedBuf();
    else if (lib_error_no != SSL_ERROR_NONE)
        return Security::ErrorString(lib_error_no);
    else
        return "[No Error]";
}

/**
 * Converts the code to a string value. Supported formating codes are:
 *
 * Error meta information:
 * %err_name: The name of a high-level SSL error (e.g., X509_V_ERR_*)
 * %ssl_error_descr: A short description of the SSL error
 * %ssl_lib_error: human-readable low-level error string by Security::ErrorString()
 *
 * Certificate information extracted from broken (not necessarily peer!) cert
 * %ssl_cn: The comma-separated list of common and alternate names
 * %ssl_subject: The certificate subject
 * %ssl_ca_name: The certificate issuer name
 * %ssl_notbefore: The certificate "not before" field
 * %ssl_notafter: The certificate "not after" field
 *
 \retval  the length of the code (the number of characters will be replaced by value)
*/
int Ssl::ErrorDetail::convert(const char *code, const char **value) const
{
    *value = "-";
    for (int i=0; ErrorFormatingCodes[i].code!=NULL; ++i) {
        const int len = strlen(ErrorFormatingCodes[i].code);
        if (strncmp(code,ErrorFormatingCodes[i].code, len)==0) {
            ErrorDetail::fmt_action_t action  = ErrorFormatingCodes[i].fmt_action;
            *value = (this->*action)();
            return len;
        }
    }
    return 0;
}

/**
 * It uses the convert method to build the string errDetailStr using
 * a template message for the current SSL error. The template messages
 * can also contain normal error pages formating codes.
 * Currently the error template messages are hard-coded
 */
void Ssl::ErrorDetail::buildDetail() const
{
    char const *s = NULL;
    char const *p;
    char const *t;
    int code_len = 0;

    if (ErrorDetailsManager::GetInstance().getErrorDetail(error_no, request, detailEntry))
        s = detailEntry.detail.termedBuf();

    if (!s)
        s = SslErrorDetailDefaultStr;

    assert(s);
    while ((p = strchr(s, '%'))) {
        errDetailStr.append(s, p - s);
        code_len = convert(++p, &t);
        if (code_len)
            errDetailStr.append(t);
        else
            errDetailStr.append("%");
        s = p + code_len;
    }
    errDetailStr.append(s, strlen(s));
}

const String &Ssl::ErrorDetail::toString() const
{
    if (errDetailStr.size() == 0)
        buildDetail();
    return errDetailStr;
}

Ssl::ErrorDetail::ErrorDetail( Security::ErrorCode err_no, X509 *cert, X509 *broken, const char *aReason): error_no (err_no), lib_error_no(SSL_ERROR_NONE), errReason(aReason)
{
    if (cert)
        peer_cert.resetAndLock(cert);

    if (broken)
        broken_cert.resetAndLock(broken);
    else
        broken_cert.resetAndLock(cert);

    detailEntry.error_no = SSL_ERROR_NONE;
}

Ssl::ErrorDetail::ErrorDetail(Ssl::ErrorDetail const &anErrDetail)
{
    error_no = anErrDetail.error_no;
    request = anErrDetail.request;

    if (anErrDetail.peer_cert.get()) {
        peer_cert.resetAndLock(anErrDetail.peer_cert.get());
    }

    if (anErrDetail.broken_cert.get()) {
        broken_cert.resetAndLock(anErrDetail.broken_cert.get());
    }

    detailEntry = anErrDetail.detailEntry;

    lib_error_no = anErrDetail.lib_error_no;
}

