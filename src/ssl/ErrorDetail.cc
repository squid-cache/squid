/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "errorpage.h"
#include "fatal.h"
#include "ssl/ErrorDetail.h"
#include "ssl/ErrorDetailManager.h"

#include <map>

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
    "X509_V_ERR_PATH_LOOP",
    "X509_V_ERR_SUITE_B_INVALID_VERSION",
    "X509_V_ERR_SUITE_B_INVALID_ALGORITHM",
    "X509_V_ERR_SUITE_B_INVALID_CURVE",
    "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM",
    "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED",
    "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256",
    "X509_V_ERR_HOSTNAME_MISMATCH",
    "X509_V_ERR_EMAIL_MISMATCH",
    "X509_V_ERR_IP_ADDRESS_MISMATCH",
    "X509_V_ERR_DANE_NO_MATCH",
    "X509_V_ERR_EE_KEY_TOO_SMALL",
    "X509_V_ERR_CA_KEY_TOO_SMALL",
    "X509_V_ERR_CA_MD_TOO_WEAK",
    "X509_V_ERR_INVALID_CALL",
    "X509_V_ERR_STORE_LOOKUP",
    "X509_V_ERR_NO_VALID_SCTS",
    "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION",
    "X509_V_ERR_OCSP_VERIFY_NEEDED",
    "X509_V_ERR_OCSP_VERIFY_FAILED",
    "X509_V_ERR_OCSP_CERT_UNKNOWN",
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

static void loadSslErrorShortcutsMap()
{
    assert(TheSslErrorShortcuts.empty());
    for (int i = 0; TheSslErrorShortcutsArray[i].name; ++i)
        TheSslErrorShortcuts[TheSslErrorShortcutsArray[i].name] = TheSslErrorShortcutsArray[i].errors;
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
        if ((SQUID_TLS_ERR_OFFSET < value && value < SQUID_TLS_ERR_END) || // custom
                (value >= 0)) { // an official error, including SSL_ERROR_NONE
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

