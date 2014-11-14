/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_PEEROPTIONS_H
#define SQUID_SRC_SECURITY_PEEROPTIONS_H

#include "SBuf.h"
#include "security/Context.h"

namespace Security
{

class PeerOptions
{
public:
    PeerOptions() : ssl(false), sslVersion(0) {}

    /// generate a security context from the configured options
    Security::ContextPointer createContext();

    bool ssl;   ///< whether SSL is to be used on this connection

    SBuf certFile;       ///< path of file containing PEM format X509 certificate
    SBuf privateKeyFile; ///< path of file containing private key in PEM format
    SBuf sslOptions;     ///< library-specific options string
    SBuf caFile;         ///< path of file containing trusted Certificate Authority
    SBuf caDir;          ///< path of directory containign a set of trusted Certificate Authorities
    SBuf crlFile;        ///< path of file containing Certificate Revoke List

    int sslVersion;
    SBuf sslCipher;
    SBuf sslFlags;
    SBuf sslDomain;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_PEEROPTIONS_H */
