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
 * A job to facilitate connecting to the HTTPS server to learn its certificate.
 *
 * The Peeker job calls FwdState::fwdStart(). There are two possible outcomes:
 *
 * Success: FwdState calls ConnStateData which pins the establihsed connection
 *          for future bumped HTTP requests (TODO: and stops this job).
 *    
 * Error: FwdState Stores the error (TODO: and this job preserves it for
 *        for serving to the client in response to the first bumped request).
 */
class ServerPeeker: public AsyncJob
{
public:
    typedef CbcPointer<ServerPeeker> Pointer;

    explicit ServerPeeker(ConnStateData *anInitiator, const char *host, const int port);

    /* AsyncJob API */
    virtual ~ServerPeeker();
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    StoreEntry *storeEntry() {return entry;}
    void noteHttpsPeeked(Comm::ConnectionPointer &serverConnection);

private:
    /// connection manager waiting for peeked server info
    CbcPointer<ConnStateData> initiator;

    /// client-Squid connection which triggered this job
    Comm::ConnectionPointer clientConnection;

    /// faked, minimal request; required by server-side API
    HttpRequest::Pointer request;

    StoreEntry *entry; ///< for receiving Squid-generated error messages
    store_client *sc; ///< dummy client to prevent entry trimming

    CBDATA_CLASS2(ServerPeeker);
};

} // namespace Ssl

#endif
