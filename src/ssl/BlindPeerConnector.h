/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_BLINDPEERCONNECTOR_H
#define SQUID_SRC_SSL_BLINDPEERCONNECTOR_H

#include "ssl/PeerConnector.h"

#if USE_OPENSSL

namespace Ssl
{

/// A simple PeerConnector for SSL/TLS cache_peers. No SslBump capabilities.
class BlindPeerConnector: public PeerConnector {
    CBDATA_CLASS(BlindPeerConnector);
public:
    BlindPeerConnector(HttpRequestPointer &aRequest,
                       const Comm::ConnectionPointer &aServerConn,
                       AsyncCall::Pointer &aCallback,
                       const AccessLogEntryPointer &alp,
                       const time_t timeout = 0) :
        AsyncJob("Ssl::BlindPeerConnector"),
        PeerConnector(aServerConn, aCallback, alp, timeout)
    {
        request = aRequest;
    }

    /* PeerConnector API */

    /// Calls parent initializeSSL, configure the created SSL object to try reuse SSL session
    /// and sets the hostname to use for certificates validation
    virtual Security::SessionPtr initializeSsl();

    /// Return the configured Security::ContextPtr object
    virtual Security::ContextPtr getSslContext();

    /// On error calls peerConnectFailed function, on success store the used SSL session
    /// for later use
    virtual void noteNegotiationDone(ErrorState *error);
};

} // namespace Ssl

#endif /* USE_OPENSSL */
#endif /* SQUID_SRC_SSL_BLINDPEERCONNECTOR_H */

