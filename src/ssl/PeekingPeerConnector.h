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

    /// Used to hold parameters for suspending and calling later the
    /// Ssl::PeekingPeerConnector::noteNegotiationError call.
    class NegotiationErrorDetails {
    public:
        NegotiationErrorDetails(int ioret, int an_ssl_error, int an_ssl_lib_error): sslIoResult(ioret), ssl_error(an_ssl_error), ssl_lib_error(an_ssl_lib_error) {}
        int sslIoResult; ///< return value from an OpenSSL IO function (eg SSL_connect)
        int ssl_error; ///< an error retrieved from SSL_get_error
        int ssl_lib_error; ///< OpenSSL library error
    };

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
    virtual void noteNegotiationError(const int result, const int ssl_error, const int ssl_lib_error);
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

    /// Resumes the noteNegotiationError call after a suspend
    void resumeNegotiationError(NegotiationErrorDetails params);

    /// Inform caller class that the SSL negotiation aborted
    void tunnelInsteadOfNegotiating();

    Comm::ConnectionPointer clientConn; ///< TCP connection to the client
    AsyncCall::Pointer closeHandler; ///< we call this when the connection closed
    bool splice; ///< whether we are going to splice or not
    bool serverCertificateHandled; ///< whether handleServerCertificate() succeeded
};

inline std::ostream &operator <<(std::ostream &os, const Ssl::PeekingPeerConnector::NegotiationErrorDetails &holder)
{
    return os << "[" << holder.sslIoResult << ", " << holder.ssl_error << ", " << holder.ssl_lib_error << "]";
}

} // namespace Ssl

#endif /* USE_OPENSSL */
#endif /* SQUID_SRC_SSL_PEEKINGPEERCONNECTOR_H */

