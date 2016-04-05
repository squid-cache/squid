/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_PEERCONNECTOR_H
#define SQUID_SRC_SSL_PEERCONNECTOR_H

#include "acl/Acl.h"
#include "base/AsyncCbdataCalls.h"
#include "base/AsyncJob.h"
#include "CommCalls.h"
#include "security/EncryptorAnswer.h"
#include "ssl/support.h"

#include <iosfwd>

#if USE_OPENSSL

class HttpRequest;
class ErrorState;
class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

namespace Ssl
{

/**
 \par
 * Connects Squid to SSL/TLS-capable peers or services.
 * Contains common code and interfaces of various specialized PeerConnectors,
 * including peer certificate validation code.
 \par
 * The caller receives a call back with Security::EncryptorAnswer. If answer.error
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
    CBDATA_CLASS(PeerConnector);

public:
    /// Callback dialier API to allow PeerConnector to set the answer.
    class CbDialer
    {
    public:
        virtual ~CbDialer() {}
        /// gives PeerConnector access to the in-dialer answer
        virtual Security::EncryptorAnswer &answer() = 0;
    };

    typedef RefCount<HttpRequest> HttpRequestPointer;

public:
    PeerConnector(const Comm::ConnectionPointer &aServerConn,
                  AsyncCall::Pointer &aCallback,
                  const AccessLogEntryPointer &alp,
                  const time_t timeout = 0);
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

    virtual Security::SessionPtr initializeSsl(); ///< Initializes SSL state

    /// Performs a single secure connection negotiation step.
    /// It is called multiple times untill the negotiation finish or aborted.
    void negotiateSsl();

    /// Called after SSL negotiations have finished. Cleans up SSL state.
    /// Returns false if we are now waiting for the certs validation job.
    /// Otherwise, returns true, regardless of negotiation success/failure.
    bool sslFinalized();

    /// Called when the SSL negotiation step aborted because data needs to
    /// be transferred to/from SSL server or on error. In the first case
    /// setups the appropriate Comm::SetSelect handler. In second case
    /// fill an error and report to the PeerConnector caller.
    void handleNegotiateError(const int result);

    /// Called when the openSSL SSL_connect fnction request more data from
    /// the remote SSL server. Sets the read timeout and sets the
    /// Squid COMM_SELECT_READ handler.
    void noteWantRead();

    /// Called when the openSSL SSL_connect function needs to write data to
    /// the remote SSL server. Sets the Squid COMM_SELECT_WRITE handler.
    virtual void noteWantWrite();

    /// Called when the SSL_connect function aborts with an SSL negotiation error
    /// \param result the SSL_connect return code
    /// \param ssl_error the error code returned from the SSL_get_error function
    /// \param ssl_lib_error the error returned from the ERR_Get_Error function
    virtual void noteSslNegotiationError(const int result, const int ssl_error, const int ssl_lib_error);

    /// Called when the SSL negotiation to the server completed and the certificates
    /// validated using the cert validator.
    /// \param error if not NULL the SSL negotiation was aborted with an error
    virtual void noteNegotiationDone(ErrorState *error) {}

    /// Must implemented by the kid classes to return the Security::ContextPtr object to use
    /// for building the SSL objects.
    virtual Security::ContextPtr getSslContext() = 0;

    /// mimics FwdState to minimize changes to FwdState::initiate/negotiateSsl
    Comm::ConnectionPointer const &serverConnection() const { return serverConn; }

    void bail(ErrorState *error); ///< Return an error to the PeerConnector caller

    /// Callback the caller class, and pass the ready to communicate secure
    /// connection or an error if PeerConnector failed.
    void callBack();

    /// If called the certificates validator will not used
    void bypassCertValidator() {useCertValidator_ = false;}

    HttpRequestPointer request; ///< peer connection trigger or cause
    Comm::ConnectionPointer serverConn; ///< TCP connection to the peer
    AccessLogEntryPointer al; ///< info for the future access.log entry
    AsyncCall::Pointer callback; ///< we call this with the results
private:
    PeerConnector(const PeerConnector &); // not implemented
    PeerConnector &operator =(const PeerConnector &); // not implemented

    /// Process response from cert validator helper
    void sslCrtvdHandleReply(Ssl::CertValidationResponsePointer);

    /// Check SSL errors returned from cert validator against sslproxy_cert_error access list
    Ssl::CertErrors *sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &, Ssl::ErrorDetail *&);

    /// A wrapper function for negotiateSsl for use with Comm::SetSelect
    static void NegotiateSsl(int fd, void *data);
    AsyncCall::Pointer closeHandler; ///< we call this when the connection closed
    time_t negotiationTimeout; ///< the SSL connection timeout to use
    time_t startTime; ///< when the peer connector negotiation started
    bool useCertValidator_; ///< whether the certificate validator should bypassed
};

} // namespace Ssl

#endif /* USE_OPENSSL */
#endif /* SQUID_SRC_SSL_PEERCONNECTOR_H */

