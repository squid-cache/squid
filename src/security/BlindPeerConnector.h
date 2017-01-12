/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_BLINDPEERCONNECTOR_H
#define SQUID_SRC_SECURITY_BLINDPEERCONNECTOR_H

#include "security/PeerConnector.h"

class ErrorState;

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

    /// Calls parent initialize(), configures the created TLS session object
    /// to try and reuse a TLS session and sets the hostname to use for
    /// certificate validation
    /// \returns true on successful initialization
    virtual bool initialize(Security::SessionPointer &);

    /// Return the configured TLS context object
    virtual Security::ContextPointer getTlsContext();

    /// On error calls peerConnectFailed().
    /// On success store the used TLS session for later use.
    virtual void noteNegotiationDone(ErrorState *);
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_BLINDPEERCONNECTOR_H */

