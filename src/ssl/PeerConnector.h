/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_SSL_PEER_CONNECTOR_H
#define SQUID_SSL_PEER_CONNECTOR_H

#include "base/AsyncCbdataCalls.h"
#include "base/AsyncJob.h"
#include "ssl/support.h"
#include <iosfwd>

class HttpRequest;
class ErrorState;

namespace Ssl
{

class ErrorDetail;
class CertValidationResponse;

/// PeerConnector results (supplied via a callback).
/// The connection to peer was secured if and only if the error member is nil.
class PeerConnectorAnswer
{
public:
    ~PeerConnectorAnswer(); ///< deletes error if it is still set
    Comm::ConnectionPointer conn; ///< peer connection (secured on success)

    /// answer recepients must clear the error member in order to keep its info
    /// XXX: We should refcount ErrorState instead of cbdata-protecting it.
    CbcPointer<ErrorState> error; ///< problem details (nil on success)
};

/**
 \par
 * Connects Squid client-side to an SSL peer (cache_peer ... ssl).
 * Handles peer certificate validation.
 * Used by TunnelStateData, FwdState, and PeerPoolMgr to start talking to an
 * SSL peer.
 \par
 * The caller receives a call back with PeerConnectorAnswer. If answer.error
 * is not nil, then there was an error and the SSL connection to the SSL peer
 * was not fully established. The error object is suitable for error response
 * generation.
 \par
 * The caller must monitor the connection for closure because this
 * job will not inform the caller about such events.
 \par
 * PeerConnector class curently supports a form of SSL negotiation timeout,
 * which accounted only when sets the read timeout from SSL peer.
 * For a complete solution, the caller must monitor the overall connection
 * establishment timeout and close the connection on timeouts. This is probably
 * better than having dedicated (or none at all!) timeouts for peer selection,
 * DNS lookup, TCP handshake, SSL handshake, etc. Some steps may have their
 * own timeout, but not all steps should be forced to have theirs. 
 * XXX: tunnel.cc and probably other subsystems does not have an "overall
 * connection establishment" timeout. We need to change their code so that they
 * start monitoring earlier and close on timeouts. This change may need to be
 * discussed on squid-dev.
 \par
 * This job never closes the connection, even on errors. If a 3rd-party
 * closes the connection, this job simply quits without informing the caller.
*/
class PeerConnector: virtual public AsyncJob
{
public:
    /// Callback dialier API to allow PeerConnector to set the answer.
    class CbDialer
    {
    public:
        virtual ~CbDialer() {}
        /// gives PeerConnector access to the in-dialer answer
        virtual PeerConnectorAnswer &answer() = 0;
    };

    typedef RefCount<HttpRequest> HttpRequestPointer;

public:
    PeerConnector(HttpRequestPointer &aRequest,
                  const Comm::ConnectionPointer &aServerConn,
                  AsyncCall::Pointer &aCallback, const time_t timeout = 0);
    virtual ~PeerConnector();

protected:
    // AsyncJob API
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    /// The comm_close callback handler.
    void commCloseHandler(const CommCloseCbParams &params);

    /// Inform us that the connection is closed. Does the required clean-up.
    void connectionClosed(const char *reason);

    /// Sets up TCP socket-related notification callbacks if things go wrong.
    /// If socket already closed return false, else install the comm_close
    /// handler to monitor the socket.
    bool prepareSocket();

    /// Sets the read timeout to avoid getting stuck while reading from a
    /// silent server
    void setReadTimeout(); 

    void initializeSsl(); ///< Initializes SSL state

    /// Performs a single secure connection negotiation step.
    /// It is called multiple times untill the negotiation finish or aborted.
    void negotiateSsl();

    /// Called when the SSL negotiation step aborted because data needs to
    /// be transferred to/from SSL server or on error. In the first case
    /// setups the appropriate Comm::SetSelect handler. In second case
    /// fill an error and report to the PeerConnector caller.
    void handleNegotiateError(const int result);

private:
    PeerConnector(const PeerConnector &); // not implemented
    PeerConnector &operator =(const PeerConnector &); // not implemented

    /// mimics FwdState to minimize changes to FwdState::initiate/negotiateSsl
    Comm::ConnectionPointer const &serverConnection() const { return serverConn; }

    void bail(ErrorState *error); ///< Return an error to the PeerConnector caller

    /// Callback the caller class, and pass the ready to communicate secure
    /// connection or an error if PeerConnector failed.
    void callBack();

    /// Process response from cert validator helper
    void sslCrtvdHandleReply(Ssl::CertValidationResponse const &);

    /// Check SSL errors returned from cert validator against sslproxy_cert_error access list
    Ssl::CertErrors *sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &, Ssl::ErrorDetail *&);

    /// Callback function called when squid receive message from cert validator helper
    static void sslCrtvdHandleReplyWrapper(void *data, Ssl::CertValidationResponse const &);

    /// A wrapper function for negotiateSsl for use with Comm::SetSelect
    static void NegotiateSsl(int fd, void *data);

    HttpRequestPointer request; ///< peer connection trigger or cause
    Comm::ConnectionPointer serverConn; ///< TCP connection to the peer
    AsyncCall::Pointer callback; ///< we call this with the results
    AsyncCall::Pointer closeHandler; ///< we call this when the connection closed
    time_t negotiationTimeout; ///< the ssl connection timeout to use
    time_t startTime; ///< when the peer connector negotiation started

    CBDATA_CLASS2(PeerConnector);
};

std::ostream &operator <<(std::ostream &os, const Ssl::PeerConnectorAnswer &a);

} // namespace Ssl

#endif /* SQUID_PEER_CONNECTOR_H */
