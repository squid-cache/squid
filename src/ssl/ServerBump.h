#ifndef _SQUID_SSL_PEEKER_H
#define _SQUID_SSL_PEEKER_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "comm/forward.h"
#include "HttpRequest.h"
#include "ip/Address.h"

class ConnStateData;

namespace Ssl
{

/**
  \ingroup ServerProtocolSSLAPI
  * Used to store bump-server-first related informations
 */
class ServerBump
{
public:
    explicit ServerBump(HttpRequest *fakeRequest);
    ~ServerBump();
    /// faked, minimal request; required by server-side API
    HttpRequest::Pointer request;
    StoreEntry *entry; ///< for receiving Squid-generated error messages
    Ssl::X509_Pointer serverCert; ///< HTTPS server certificate
    Ssl::Errors *bumpSslErrorNoList; ///< The list of SSL certificate errors which ignored

private:
    store_client *sc; ///< dummy client to prevent entry trimming

    CBDATA_CLASS2(ServerBump);
};

} // namespace Ssl

#endif
