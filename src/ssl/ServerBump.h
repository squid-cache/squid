/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "security/forward.h"

class ConnStateData;
class store_client;

namespace Ssl
{

/**
 * Maintains bump-server-first related information.
 */
class ServerBump
{
    CBDATA_CLASS(ServerBump);

public:
    explicit ServerBump(HttpRequest *fakeRequest, StoreEntry *e = NULL, Ssl::BumpMode mode = Ssl::bumpServerFirst);
    ~ServerBump();
    void attachServerSSL(SSL *); ///< Sets the server SSL object
    const Security::CertErrors *sslErrors() const; ///< SSL [certificate validation] errors

    /// faked, minimal request; required by Client API
    HttpRequest::Pointer request;
    StoreEntry *entry; ///< for receiving Squid-generated error messages
    /// HTTPS server certificate. Maybe it is different than the one
    /// it is stored in serverSSL object (error SQUID_X509_V_ERR_CERT_CHANGE)
    Security::CertPointer serverCert;
    struct {
        Ssl::BumpMode step1; ///< The SSL bump mode at step1
        Ssl::BumpMode step2; ///< The SSL bump mode at step2
        Ssl::BumpMode step3; ///< The SSL bump mode at step3
    } act; ///< bumping actions at various bumping steps
    Ssl::BumpStep step; ///< The SSL bumping step
    SBuf clientSni; ///< the SSL client SNI name
    Security::SessionPointer serverSSL; ///< The SSL object on server side.

private:
    store_client *sc; ///< dummy client to prevent entry trimming
};

} // namespace Ssl

#endif

