/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "globals.h"
#include "parser/Tokenizer.h"
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
        debugs(0, DBG_PARSE_NOTE(1), "UPGRADE WARNING: SSL version= is deprecated. Use options= to limit protocols instead.");
        sslVersion = xatoi(token + 8);
    } else if (strncmp(token, "min-version=", 12) == 0) {
        tlsMinVersion = SBuf(token + 12);
    } else if (strncmp(token, "options=", 8) == 0) {
        sslOptions = SBuf(token + 8);
#if USE_OPENSSL
        // Pre-parse SSL client options to be applied when the client SSL objects created.
        // Options must not used in the case of peek or stare bump mode.
        // XXX: performance regression. c_str() can reallocate
        parsedOptions = Ssl::parse_options(sslOptions.c_str());
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
Security::PeerOptions::createContext(bool setOptions)
{
    Security::ContextPointer t = NULL;

    if (!tlsMinVersion.isEmpty()) {
        ::Parser::Tokenizer tok(tlsMinVersion);
        int64_t v = 0;
        if (tok.skip('1') && tok.skip('.') && tok.int64(v, 10, false, 1) && v <= 2) {
            // only account for TLS here - SSL versions are handled by options= parameter
            if (v > 0)
                sslOptions.append(",NO_TLSv1",9);
            if (v > 1)
                sslOptions.append(",NO_TLSv1_1",11);
            if (v > 2)
                sslOptions.append(",NO_TLSv1_2",11);

        } else {
            debugs(0, DBG_PARSE_NOTE(1), "WARNING: Unknown TLS minimum version: " << tlsMinVersion);
        }

    } else if (sslVersion > 2) {
        // backward compatibility hack for sslversion= configuration
        // only use if tls-min-version=N.N is not present

        const char *add = NULL;
        switch (sslVersion) {
        case 3:
            add = "NO_TLSv1,NO_TLSv1_1,NO_TLSv1_2";
            break;
        case 4:
            add = "NO_SSLv3,NO_TLSv1_1,NO_TLSv1_2";
            break;
        case 5:
            add = "NO_SSLv3,NO_TLSv1,NO_TLSv1_2";
            break;
        case 6:
            add = "NO_SSLv3,NO_TLSv1,NO_TLSv1_1";
            break;
        default: // nothing
            break;
        }
        if (add) {
            if (!sslOptions.isEmpty())
                sslOptions.append(",",1);
            sslOptions.append(add, strlen(add));
        }
        sslVersion = 0; // prevent sslOptions being repeatedly appended
    }

#if USE_OPENSSL
    // XXX: temporary performance regression. c_str() data copies and prevents this being a const method
    t = sslCreateClientContext(certFile.c_str(), privateKeyFile.c_str(), sslCipher.c_str(),
                               (setOptions ? sslOptions.c_str() : NULL), sslFlags.c_str(),
                               caFile.c_str(), caDir.c_str(), crlFile.c_str());
#endif

    return t;
}

void
parse_securePeerOptions(Security::PeerOptions *opt)
{
    while(const char *token = ConfigParser::NextToken())
        opt->parse(token);
}

