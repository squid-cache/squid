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
    explicit ServerBump(HttpRequest *fakeRequest, StoreEntry *e = NULL);
    ~ServerBump();

    /// faked, minimal request; required by server-side API
    HttpRequest::Pointer request;
    StoreEntry *entry; ///< for receiving Squid-generated error messages
    Ssl::X509_Pointer serverCert; ///< HTTPS server certificate
    Ssl::CertErrors *sslErrors; ///< SSL [certificate validation] errors

private:
    store_client *sc; ///< dummy client to prevent entry trimming

    CBDATA_CLASS2(ServerBump);
};

} // namespace Ssl

#endif
