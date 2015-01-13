/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SSL_PEEKER_H
#define _SQUID_SSL_PEEKER_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "comm/forward.h"
#include "HttpRequest.h"
#include "ip/Address.h"

class ConnStateData;
class store_client;

namespace Ssl
{

/**
  \ingroup ServerProtocolSSLAPI
 * Maintains bump-server-first related information.
 */
class ServerBump
{
public:
    explicit ServerBump(HttpRequest *fakeRequest, StoreEntry *e = NULL, Ssl::BumpMode mode = Ssl::bumpServerFirst);
    ~ServerBump();

    /// faked, minimal request; required by Client API
    HttpRequest::Pointer request;
    StoreEntry *entry; ///< for receiving Squid-generated error messages
    Ssl::X509_Pointer serverCert; ///< HTTPS server certificate
    Ssl::CertErrors *sslErrors; ///< SSL [certificate validation] errors
    struct {
        Ssl::BumpMode step1; ///< The SSL bump mode at step1
        Ssl::BumpMode step2; ///< The SSL bump mode at step2
        Ssl::BumpMode step3; ///< The SSL bump mode at step3
    } act; ///< bumping actions at various bumping steps
    Ssl::BumpStep step; ///< The SSL bumping step
    SBuf clientSni; ///< the SSL client SNI name

private:
    store_client *sc; ///< dummy client to prevent entry trimming

    CBDATA_CLASS2(ServerBump);
};

} // namespace Ssl

#endif

