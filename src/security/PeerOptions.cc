/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
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
Security::PeerOptions::createContext()
{
    Security::ContextPointer t = NULL;

    if (privateKeyFile.isEmpty())
        privateKeyFile = certFile;

#if USE_OPENSSL
    t = sslCreateClientContext(certFile.c_str(), privateKeyFile.c_str(), sslVersion, sslCipher.c_str(),
                           sslOptions.c_str(), sslFlags.c_str(), caFile.c_str(), caDir.c_str(), crlFile.c_str());
#endif
    return t;
}
