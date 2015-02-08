/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_PEEROPTIONS_H
#define SQUID_SRC_SECURITY_PEEROPTIONS_H

#include "ConfigParser.h"
#include "SBuf.h"
#include "security/Context.h"

namespace Security
{

/// TLS squid.conf settings for a remote server peer
class PeerOptions
{
public:
    PeerOptions() : sslVersion(0), encryptTransport(false) {}

    /// parse a TLS squid.conf option
    void parse(const char *);

    /// reset the configuration details to default
    void clear() {*this = PeerOptions();}

    /// generate a security context from these configured options
    Security::ContextPointer createContext();

    SBuf certFile;       ///< path of file containing PEM format X509 certificate
    SBuf privateKeyFile; ///< path of file containing private key in PEM format
    SBuf sslOptions;     ///< library-specific options string
    SBuf caFile;         ///< path of file containing trusted Certificate Authority
    SBuf caDir;          ///< path of directory containing a set of trusted Certificate Authorities
    SBuf crlFile;        ///< path of file containing Certificate Revoke List

    SBuf sslCipher;
    SBuf sslFlags;
    SBuf sslDomain;

    int sslVersion;

    /// whether transport encryption (TLS/SSL) is to be used on connections to the peer
    bool encryptTransport;
};

/// configuration options for DIRECT server access
extern PeerOptions ProxyOutgoingConfig;

} // namespace Security

// parse the tls_outgoing_options directive
void parse_securePeerOptions(Security::PeerOptions *);
#define free_securePeerOptions(x) Security::ProxyOutgoingConfig.clear()
#define dump_securePeerOptions(e,n,x) // not supported yet

#endif /* SQUID_SRC_SECURITY_PEEROPTIONS_H */
