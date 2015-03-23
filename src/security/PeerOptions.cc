/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"
#include "Parsing.h"
#include "security/PeerOptions.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

Security::PeerOptions Security::ProxyOutgoingConfig;

void
Security::PeerOptions::parse(const char *token)
{
    if (strncmp(token, "cert=", 5) == 0) {
        certFile = SBuf(token + 5);
        if (privateKeyFile.isEmpty())
            privateKeyFile = certFile;
    } else if (strncmp(token, "key=", 4) == 0) {
        privateKeyFile = SBuf(token + 4);
        if (certFile.isEmpty()) {
            debugs(0, DBG_PARSE_NOTE(1), "WARNING: cert= option needs to be set before key= is used.");
            certFile = privateKeyFile;
        }
    } else if (strncmp(token, "version=", 8) == 0) {
        sslVersion = xatoi(token + 8);
    } else if (strncmp(token, "options=", 8) == 0) {
        sslOptions = SBuf(token + 8);
#if USE_OPENSSL
        // Pre-parse SSL client options to be applied when the client SSL objects created.
        // Options must not used in the case of peek or stare bump mode.
        // XXX: performance regression. c_str() can reallocate
        parsedOptions = Security::ParseOptions(sslOptions.c_str());
#endif
    } else if (strncmp(token, "cipher=", 7) == 0) {
        sslCipher = SBuf(token + 7);
    } else if (strncmp(token, "cafile=", 7) == 0) {
        caFile = SBuf(token + 7);
    } else if (strncmp(token, "capath=", 7) == 0) {
        caDir = SBuf(token + 7);
    } else if (strncmp(token, "crlfile=", 8) == 0) {
        crlFile = SBuf(token + 8);
    } else if (strncmp(token, "flags=", 6) == 0) {
        sslFlags = SBuf(token + 6);
    } else if (strncmp(token, "domain=", 7) == 0) {
        sslDomain = SBuf(token + 7);
    }
}

// XXX: make a GnuTLS variant
Security::ContextPointer
Security::PeerOptions::createClientContext(bool setOptions)
{
    Security::ContextPointer t = NULL;

#if USE_OPENSSL
    // XXX: temporary performance regression. c_str() data copies and prevents this being a const method
    t = sslCreateClientContext(certFile.c_str(), privateKeyFile.c_str(), sslVersion, sslCipher.c_str(),
                               (setOptions ? parsedOptions : 0), sslFlags.c_str(), caFile.c_str(), caDir.c_str(), crlFile.c_str());

#endif

    return t;
}

/// set of options we can parse and what they map to
static struct ssl_option {
    const char *name;
    long value;

} ssl_options[] = {

#if SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    {
        "NETSCAPE_REUSE_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    },
#endif
#if SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    {
        "SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    },
#endif
#if SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    {
        "MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    },
#endif
#if SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    {
        "SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    },
#endif
#if SSL_OP_TLS_D5_BUG
    {
        "TLS_D5_BUG", SSL_OP_TLS_D5_BUG
    },
#endif
#if SSL_OP_TLS_BLOCK_PADDING_BUG
    {
        "TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG
    },
#endif
#if SSL_OP_TLS_ROLLBACK_BUG
    {
        "TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG
    },
#endif
#if SSL_OP_ALL
    {
        "ALL", (long)SSL_OP_ALL
    },
#endif
#if SSL_OP_SINGLE_DH_USE
    {
        "SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE
    },
#endif
#if SSL_OP_EPHEMERAL_RSA
    {
        "EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA
    },
#endif
#if SSL_OP_PKCS1_CHECK_1
    {
        "PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1
    },
#endif
#if SSL_OP_PKCS1_CHECK_2
    {
        "PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2
    },
#endif
#if SSL_OP_NETSCAPE_CA_DN_BUG
    {
        "NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG
    },
#endif
#if SSL_OP_NON_EXPORT_FIRST
    {
        "NON_EXPORT_FIRST", SSL_OP_NON_EXPORT_FIRST
    },
#endif
#if SSL_OP_CIPHER_SERVER_PREFERENCE
    {
        "CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE
    },
#endif
#if SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
    {
        "NETSCAPE_DEMO_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
    },
#endif
#if SSL_OP_NO_SSLv3
    {
        "NO_SSLv3", SSL_OP_NO_SSLv3
    },
#endif
#if SSL_OP_NO_TLSv1
    {
        "NO_TLSv1", SSL_OP_NO_TLSv1
    },
#endif
#if SSL_OP_NO_TLSv1_1
    {
        "NO_TLSv1_1", SSL_OP_NO_TLSv1_1
    },
#endif
#if SSL_OP_NO_TLSv1_2
    {
        "NO_TLSv1_2", SSL_OP_NO_TLSv1_2
    },
#endif
#if SSL_OP_NO_COMPRESSION
    {
        "No_Compression", SSL_OP_NO_COMPRESSION
    },
#endif
#if SSL_OP_NO_TICKET
    {
        "NO_TICKET", SSL_OP_NO_TICKET
    },
#endif
    {
        "", 0
    },
    {
        NULL, 0
    }
};

long
Security::ParseOptions(const char *options)
{
    long op = 0;
    char *tmp;
    char *option;

    if (options) {

    tmp = xstrdup(options);
    option = strtok(tmp, ":,");

    while (option) {

        enum {
            MODE_ADD, MODE_REMOVE
        } mode;

        switch (*option) {

        case '!':

        case '-':
            mode = MODE_REMOVE;
            ++option;
            break;

        case '+':
            mode = MODE_ADD;
            ++option;
            break;

        default:
            mode = MODE_ADD;
            break;
        }

        struct ssl_option *opt = NULL;
        for (struct ssl_option *opttmp = ssl_options; opttmp->name; ++opttmp) {
            if (strcmp(opttmp->name, option) == 0) {
                opt = opttmp;
                break;
            }
        }

        long value = 0;
        if (opt)
            value = opt->value;
        else if (strncmp(option, "0x", 2) == 0) {
            /* Special case.. hex specification */
            value = strtol(option + 2, NULL, 16);
        } else {
            fatalf("Unknown SSL option '%s'", option);
            value = 0;      /* Keep GCC happy */
        }

        switch (mode) {

        case MODE_ADD:
            op |= value;
            break;

        case MODE_REMOVE:
            op &= ~value;
            break;
        }

        option = strtok(NULL, ":,");
    }

    safe_free(tmp);
    }

#if SSL_OP_NO_SSLv2
    // compliance with RFC 6176: Prohibiting Secure Sockets Layer (SSL) Version 2.0
    op = op | SSL_OP_NO_SSLv2;
#endif
    return op;
}

void
parse_securePeerOptions(Security::PeerOptions *opt)
{
    while(const char *token = ConfigParser::NextToken())
        opt->parse(token);
}

