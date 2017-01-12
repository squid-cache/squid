/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_KEYDATA_H
#define SQUID_SRC_SECURITY_KEYDATA_H

#include "sbuf/SBuf.h"
#include "security/forward.h"

namespace Security
{

/// TLS certificate and private key details from squid.conf
class KeyData
{
public:
    SBuf certFile;       ///< path of file containing PEM format X.509 certificate
    SBuf privateKeyFile; ///< path of file containing private key in PEM format
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_KEYDATA_H */

