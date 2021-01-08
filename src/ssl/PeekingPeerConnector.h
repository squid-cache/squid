/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_PEEKINGPEERCONNECTOR_H
#define SQUID_SRC_SSL_PEEKINGPEERCONNECTOR_H

#include "security/PeerConnector.h"

#if USE_OPENSSL

namespace Ssl
{

/// A PeerConnector for HTTP origin servers. Capable of SslBumping.
class PeekingPeerConnector: public Security::PeerConnector {
    CBDATA_CLASS(PeekingPeerConnector);
public:
    PeekingPeerConnector(HttpRequestPointer &aRequest,
                         const Comm::ConnectionPointer &aServerConn,
                         const Comm::ConnectionPointer &aClientConn,
                         AsyncCall::Pointer &aCallback,
                         const AccessLogEntryPointer &alp,
                         const time_t timeout = 0) :
        AsyncJob("Ssl::PeekingPeerConnector"),
        Security::PeerConnector(aServerConn, aCallback, alp, timeout),
        clientConn(aClientConn),
        splice(false),
        serverCertificateHandled(false)
    {
        request = aRequest;
    }

    /* Security::PeerConnector API */
    virtual bool initialize(Security::SessionPointer &);
    virtual Security::ContextPointer getTlsContext();
    virtual void noteWantWrite();
    virtual void noteNegotiationError(const Security::ErrorDetailPointer &);
    virtual void noteNegotiationDone(ErrorState *error);

    /// Updates associated client connection manager members
    /// if the server certificate was received from the server.
    void handleServerCertificate();

    /// Initiates the ssl_bump acl check in step3 SSL bump step to decide
    /// about bumping, splicing or terminating the connection.
    void checkForPeekAndSplice();

    /// Callback function for ssl_bump acl check in step3  SSL bump step.
    void checkForPeekAndSpliceDone(Acl::Answer answer);

    /// Handles the final bumping decision.
    void checkForPeekAndSpliceMatched(const Ssl::BumpMode finalMode);

    /// Guesses the final bumping decision when no ssl_bump rules match.
    Ssl::BumpMode checkForPeekAndSpliceGuess() const;

    /// Runs after the server certificate verified to update client
    /// connection manager members
    void serverCertificateVerified();

    /// Abruptly stops TLS negotiation and starts tunneling.
    void startTunneling();

    /// A wrapper function for checkForPeekAndSpliceDone for use with acl
    static void cbCheckForPeekAndSpliceDone(Acl::Answer answer, void *data);

private:

    /// Inform caller class that the SSL negotiation aborted
    void tunnelInsteadOfNegotiating();

    Comm::ConnectionPointer clientConn; ///< TCP connection to the client
    AsyncCall::Pointer closeHandler; ///< we call this when the connection closed
    bool splice; ///< whether we are going to splice or not
    bool serverCertificateHandled; ///< whether handleServerCertificate() succeeded
};

} // namespace Ssl

#endif /* USE_OPENSSL */
#endif /* SQUID_SRC_SSL_PEEKINGPEERCONNECTOR_H */

