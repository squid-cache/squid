/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_BLINDPEERCONNECTOR_H
#define SQUID_SRC_SSL_BLINDPEERCONNECTOR_H

#include "security/PeerConnector.h"

namespace Security
{

/// A simple PeerConnector for SSL/TLS cache_peers. No SslBump capabilities.
class BlindPeerConnector: public Security::PeerConnector {
    CBDATA_CLASS(BlindPeerConnector);
public:
    BlindPeerConnector(HttpRequestPointer &aRequest,
                       const Comm::ConnectionPointer &aServerConn,
                       AsyncCall::Pointer &aCallback,
                       const AccessLogEntryPointer &alp,
                       const time_t timeout = 0) :
        AsyncJob("Security::BlindPeerConnector"),
        Security::PeerConnector(aServerConn, aCallback, alp, timeout)
    {
        request = aRequest;
    }

    /* Security::PeerConnector API */

    /// Calls parent initializeTls(), configure the created TLS session object to
    ///  try reuse TLS session and sets the hostname to use for certificates validation
    /// \returns true on successful initialization
    virtual bool initializeTls(Security::SessionPointer &);

    /// Return the configured Security::ContextPtr object
    virtual Security::ContextPtr getSslContext();

    /// On error calls peerConnectFailed function, on success store the used SSL session
    /// for later use
    virtual void noteNegotiationDone(ErrorState *error);
};

} // namespace Security

#endif /* SQUID_SRC_SSL_BLINDPEERCONNECTOR_H */

