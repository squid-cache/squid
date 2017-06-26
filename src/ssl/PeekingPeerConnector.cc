/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL-Bump Server/Peer negotiation */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "errorpage.h"
#include "fde.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "security/NegotiationHistory.h"
#include "SquidConfig.h"
#include "ssl/bio.h"
#include "ssl/PeekingPeerConnector.h"
#include "ssl/ServerBump.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, PeekingPeerConnector);

void switchToTunnel(HttpRequest *request, Comm::ConnectionPointer & clientConn, Comm::ConnectionPointer &srvConn);

void
Ssl::PeekingPeerConnector::cbCheckForPeekAndSpliceDone(allow_t answer, void *data)
{
    Ssl::PeekingPeerConnector *peerConnect = (Ssl::PeekingPeerConnector *) data;
    // Use job calls to add done() checks and other job logic/protections.
    CallJobHere1(83, 7, CbcPointer<PeekingPeerConnector>(peerConnect), Ssl::PeekingPeerConnector, checkForPeekAndSpliceDone, answer);
}

void
Ssl::PeekingPeerConnector::checkForPeekAndSpliceDone(allow_t answer)
{
    const Ssl::BumpMode finalAction = answer.allowed() ?
                                      static_cast<Ssl::BumpMode>(answer.kind):
                                      checkForPeekAndSpliceGuess();
    checkForPeekAndSpliceMatched(finalAction);
}

void
Ssl::PeekingPeerConnector::checkForPeekAndSplice()
{
    // Mark Step3 of bumping
    if (request->clientConnectionManager.valid()) {
        if (Ssl::ServerBump *serverBump = request->clientConnectionManager->serverBump()) {
            serverBump->step = Ssl::bumpStep3;
        }
    }

    handleServerCertificate();

    ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(
        ::Config.accessList.ssl_bump,
        request.getRaw(), NULL);
    acl_checklist->al = al;
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpNone));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpPeek));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpStare));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpClientFirst));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpServerFirst));
    Security::SessionPointer session(fd_table[serverConn->fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    if (!srvBio->canSplice())
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpSplice));
    if (!srvBio->canBump())
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpBump));
    acl_checklist->nonBlockingCheck(Ssl::PeekingPeerConnector::cbCheckForPeekAndSpliceDone, this);
}

void
Ssl::PeekingPeerConnector::checkForPeekAndSpliceMatched(const Ssl::BumpMode action)
{
    Security::SessionPointer session(fd_table[serverConn->fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    debugs(83,5, "Will check for peek and splice on FD " << serverConn->fd);

    Ssl::BumpMode finalAction = action;
    Must(finalAction == Ssl::bumpSplice || finalAction == Ssl::bumpBump || finalAction == Ssl::bumpTerminate);
    // Record final decision
    if (request->clientConnectionManager.valid()) {
        request->clientConnectionManager->sslBumpMode = finalAction;
        request->clientConnectionManager->serverBump()->act.step3 = finalAction;
    }
    al->ssl.bumpMode = finalAction;

    if (finalAction == Ssl::bumpTerminate) {
        serverConn->close();
        clientConn->close();
    } else if (finalAction != Ssl::bumpSplice) {
        //Allow write, proceed with the connection
        srvBio->holdWrite(false);
        srvBio->recordInput(false);
        debugs(83,5, "Retry the fwdNegotiateSSL on FD " << serverConn->fd);
        Security::PeerConnector::noteWantWrite();
    } else {
        splice = true;
        // Ssl Negotiation stops here. Last SSL checks for valid certificates
        // and if done, switch to tunnel mode
        if (sslFinalized()) {
            debugs(83,5, "Abort NegotiateSSL on FD " << serverConn->fd << " and splice the connection");
            callBack();
        }
    }
}

Ssl::BumpMode
Ssl::PeekingPeerConnector::checkForPeekAndSpliceGuess() const
{
    if (const ConnStateData *csd = request->clientConnectionManager.valid()) {
        const Ssl::BumpMode currentMode = csd->sslBumpMode;
        if (currentMode == Ssl::bumpStare) {
            debugs(83,5, "default to bumping after staring");
            return Ssl::bumpBump;
        }
        debugs(83,5, "default to splicing after " << currentMode);
    } else {
        debugs(83,3, "default to splicing due to missing info");
    }

    return Ssl::bumpSplice;
}

Security::ContextPointer
Ssl::PeekingPeerConnector::getTlsContext()
{
    return ::Config.ssl_client.sslContext;
}

bool
Ssl::PeekingPeerConnector::initialize(Security::SessionPointer &serverSession)
{
    if (!Security::PeerConnector::initialize(serverSession))
        return false;

    if (ConnStateData *csd = request->clientConnectionManager.valid()) {

        // client connection is required in the case we need to splice
        // or terminate client and server connections
        assert(clientConn != NULL);
        SBuf *hostName = NULL;

        //Enable Status_request TLS extension, required to bump some clients
        SSL_set_tlsext_status_type(serverSession.get(), TLSEXT_STATUSTYPE_ocsp);

        const Security::TlsDetails::Pointer details = csd->tlsParser.details;
        if (details && !details->serverName.isEmpty())
            hostName = new SBuf(details->serverName);

        if (!hostName) {
            // While we are peeking at the certificate, we may not know the server
            // name that the client will request (after interception or CONNECT)
            // unless it was the CONNECT request with a user-typed address.
            const bool isConnectRequest = !csd->port->flags.isIntercepted();
            if (!request->flags.sslPeek || isConnectRequest)
                hostName = new SBuf(request->url.host());
        }

        if (hostName)
            SSL_set_ex_data(serverSession.get(), ssl_ex_index_server, (void*)hostName);

        Must(!csd->serverBump() || csd->serverBump()->step <= Ssl::bumpStep2);
        if (csd->sslBumpMode == Ssl::bumpPeek || csd->sslBumpMode == Ssl::bumpStare) {
            auto clientSession = fd_table[clientConn->fd].ssl.get();
            Must(clientSession);
            BIO *bc = SSL_get_rbio(clientSession);
            Ssl::ClientBio *cltBio = static_cast<Ssl::ClientBio *>(BIO_get_data(bc));
            Must(cltBio);
            if (details && details->tlsVersion.protocol != AnyP::PROTO_NONE)
                applyTlsDetailsToSSL(serverSession.get(), details, csd->sslBumpMode);

            BIO *b = SSL_get_rbio(serverSession.get());
            Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
            Must(srvBio);
            // inherit client features such as TLS version and SNI
            srvBio->setClientFeatures(details, cltBio->rBufData());
            srvBio->recordInput(true);
            srvBio->mode(csd->sslBumpMode);
        } else {
            // Set client SSL options
            SSL_set_options(serverSession.get(), ::Security::ProxyOutgoingConfig.parsedOptions);

            // Use SNI TLS extension only when we connect directly
            // to the origin server and we know the server host name.
            const char *sniServer = NULL;
            const bool redirected = request->flags.redirected && ::Config.onoff.redir_rewrites_host;
            if (!hostName || redirected)
                sniServer = !request->url.hostIsNumeric() ? request->url.host() : NULL;
            else
                sniServer = hostName->c_str();

            if (sniServer)
                Ssl::setClientSNI(serverSession.get(), sniServer);
        }

        if (Ssl::ServerBump *serverBump = csd->serverBump()) {
            serverBump->attachServerSession(serverSession);
            // store peeked cert to check SQUID_X509_V_ERR_CERT_CHANGE
            if (X509 *peeked_cert = serverBump->serverCert.get()) {
                X509_up_ref(peeked_cert);
                SSL_set_ex_data(serverSession.get(), ssl_ex_index_ssl_peeked_cert, peeked_cert);
            }
        }
    }

    return true;
}

void
Ssl::PeekingPeerConnector::noteNegotiationDone(ErrorState *error)
{
    // Check the list error with
    if (!request->clientConnectionManager.valid() || !fd_table[serverConnection()->fd].ssl)
        return;

    // remember the server certificate from the ErrorDetail object
    if (Ssl::ServerBump *serverBump = request->clientConnectionManager->serverBump()) {
        if (!serverBump->serverCert.get()) {
            // remember the server certificate from the ErrorDetail object
            if (error && error->detail && error->detail->peerCert())
                serverBump->serverCert.resetAndLock(error->detail->peerCert());
            else {
                handleServerCertificate();
            }
        }

        if (error) {
            // For intercepted connections, set the host name to the server
            // certificate CN. Otherwise, we just hope that CONNECT is using
            // a user-entered address (a host name or a user-entered IP).
            const bool isConnectRequest = !request->clientConnectionManager->port->flags.isIntercepted();
            if (request->flags.sslPeek && !isConnectRequest) {
                if (X509 *srvX509 = serverBump->serverCert.get()) {
                    if (const char *name = Ssl::CommonHostName(srvX509)) {
                        request->url.host(name);
                        debugs(83, 3, "reset request host: " << name);
                    }
                }
            }
        }
    }

    if (!error) {
        serverCertificateVerified();
        if (splice) {
            switchToTunnel(request.getRaw(), clientConn, serverConn);
            tunnelInsteadOfNegotiating();
        }
    }
}

void
Ssl::PeekingPeerConnector::noteWantWrite()
{
    const int fd = serverConnection()->fd;
    Security::SessionPointer session(fd_table[fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));

    if ((srvBio->bumpMode() == Ssl::bumpPeek || srvBio->bumpMode() == Ssl::bumpStare) && srvBio->holdWrite()) {
        debugs(81, 3, "hold write on SSL connection on FD " << fd);
        checkForPeekAndSplice();
        return;
    }

    Security::PeerConnector::noteWantWrite();
}

void
Ssl::PeekingPeerConnector::noteNegotiationError(const int result, const int ssl_error, const int ssl_lib_error)
{
    const int fd = serverConnection()->fd;
    Security::SessionPointer session(fd_table[fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));

    // In Peek mode, the ClientHello message sent to the server. If the
    // server resuming a previous (spliced) SSL session with the client,
    // then probably we are here because local SSL object does not know
    // anything about the session being resumed.
    //
    if (srvBio->bumpMode() == Ssl::bumpPeek && (resumingSession = srvBio->resumingSession())) {
        // we currently splice all resumed sessions unconditionally
        if (const bool spliceResumed = true) {
            bypassCertValidator();
            checkForPeekAndSpliceMatched(Ssl::bumpSplice);
            return;
        } // else fall through to find a matching ssl_bump action (with limited info)
    }

    // If we are in peek-and-splice mode and still we did not write to
    // server yet, try to see if we should splice.
    // In this case the connection can be saved.
    // If the checklist decision is do not splice a new error will
    // occur in the next SSL_connect call, and we will fail again.
    // Abort on certificate validation errors to avoid splicing and
    // thus hiding them.
    // Abort if no certificate found probably because of malformed or
    // unsupported server Hello message (TODO: make configurable).
    if (!SSL_get_ex_data(session.get(), ssl_ex_index_ssl_error_detail) &&
            (srvBio->bumpMode() == Ssl::bumpPeek  || srvBio->bumpMode() == Ssl::bumpStare) && srvBio->holdWrite()) {
        Security::CertPointer serverCert(SSL_get_peer_certificate(session.get()));
        if (serverCert) {
            debugs(81, 3, "Error ("  << Security::ErrorString(ssl_lib_error) <<  ") but, hold write on SSL connection on FD " << fd);
            checkForPeekAndSplice();
            return;
        }
    }

    // else call parent noteNegotiationError to produce an error page
    Security::PeerConnector::noteNegotiationError(result, ssl_error, ssl_lib_error);
}

void
Ssl::PeekingPeerConnector::handleServerCertificate()
{
    if (serverCertificateHandled)
        return;

    if (ConnStateData *csd = request->clientConnectionManager.valid()) {
        const int fd = serverConnection()->fd;
        Security::SessionPointer session(fd_table[fd].ssl);
        Security::CertPointer serverCert(SSL_get_peer_certificate(session.get()));
        if (!serverCert)
            return;

        serverCertificateHandled = true;

        // remember the server certificate for later use
        if (Ssl::ServerBump *serverBump = csd->serverBump()) {
            serverBump->serverCert = std::move(serverCert);
        }
    }
}

void
Ssl::PeekingPeerConnector::serverCertificateVerified()
{
    if (ConnStateData *csd = request->clientConnectionManager.valid()) {
        Security::CertPointer serverCert;
        if(Ssl::ServerBump *serverBump = csd->serverBump())
            serverCert.resetAndLock(serverBump->serverCert.get());
        else {
            const int fd = serverConnection()->fd;
            Security::SessionPointer session(fd_table[fd].ssl);
            serverCert.resetWithoutLocking(SSL_get_peer_certificate(session.get()));
        }
        if (serverCert) {
            csd->resetSslCommonName(Ssl::CommonHostName(serverCert.get()));
            debugs(83, 5, "HTTPS server CN: " << csd->sslCommonName() <<
                   " bumped: " << *serverConnection());
        }
    }
}

void
Ssl::PeekingPeerConnector::tunnelInsteadOfNegotiating()
{
    Must(callback != NULL);
    CbDialer *dialer = dynamic_cast<CbDialer*>(callback->getDialer());
    Must(dialer);
    dialer->answer().tunneled = true;
    debugs(83, 5, "The SSL negotiation with server aborted");
}

