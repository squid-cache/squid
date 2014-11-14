/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "security/PeerOptions.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

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
