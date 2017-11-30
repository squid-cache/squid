/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_KEYDATA_H
#define SQUID_SRC_SECURITY_KEYDATA_H

#include "anyp/forward.h"
#include "sbuf/SBuf.h"
#include "security/forward.h"

namespace Security
{

/// TLS certificate and private key details from squid.conf
class KeyData
{
public:
    /// load the contents of certFile and privateKeyFile into memory cert, pkey and chain
    void loadFromFiles(const AnyP::PortCfg &, const char *portType);

public:
    SBuf certFile;       ///< path of file containing PEM format X.509 certificate
    SBuf privateKeyFile; ///< path of file containing private key in PEM format

    /// memory copy of the X.509 certificate from certFile
    Security::CertPointer cert;
    /// memory copy of the private key from privateKeyFile (which may be the same as certFile)
    Security::PrivateKeyPointer pkey;
    /// memory copy of any certificates which must be chained from cert
    Security::CertList chain;

private:
    bool checkPrivateKey();
    bool loadX509CertFromFile();
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_KEYDATA_H */

