/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "security/ErrorDetail.h"
#include "security/NegotiationHistory.h"
#include "SquidConfig.h"
#include "ssl/bio.h"
#include "ssl/PeekingPeerConnector.h"
#include "ssl/ServerBump.h"
#include "tunnel.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, PeekingPeerConnector);

Ssl::PeekingPeerConnector::PeekingPeerConnector(HttpRequestPointer &aRequest,
        const Comm::ConnectionPointer &aServerConn,
        const Comm::ConnectionPointer &aClientConn,
        const AsyncCallback<Security::EncryptorAnswer> &aCallback,
        const AccessLogEntryPointer &alp,
        const time_t timeout):
    AsyncJob("Ssl::PeekingPeerConnector"),
    Security::PeerConnector(aServerConn, aCallback, alp, timeout),
    clientConn(aClientConn),
    splice(false),
    serverCertificateHandled(false)
{
    request = aRequest;

    if (const auto csd = request->clientConnectionManager.valid()) {
        const auto serverBump = csd->serverBump();
        Must(serverBump);
        Must(serverBump->at(XactionStep::tlsBump3));
    }
    // else the client is gone, and we cannot check the step, but must carry on
}

void
Ssl::PeekingPeerConnector::cbCheckForPeekAndSpliceDone(const Acl::Answer aclAnswer, void *data)
{
    Ssl::PeekingPeerConnector *peerConnect = (Ssl::PeekingPeerConnector *) data;
    // Use job calls to add done() checks and other job logic/protections.
    CallJobHere1(83, 7, CbcPointer<PeekingPeerConnector>(peerConnect), Ssl::PeekingPeerConnector, checkForPeekAndSpliceDone, aclAnswer);
}

void
Ssl::PeekingPeerConnector::checkForPeekAndSpliceDone(const Acl::Answer aclAnswer)
{
    const Ssl::BumpMode finalAction = aclAnswer.allowed() ?
                                      static_cast<Ssl::BumpMode>(aclAnswer.kind):
                                      checkForPeekAndSpliceGuess();
    checkForPeekAndSpliceMatched(finalAction);
}

void
Ssl::PeekingPeerConnector::checkForPeekAndSplice()
{
    handleServerCertificate();

    ACLFilledChecklist *acl_checklist = new ACLFilledChecklist(
        ::Config.accessList.ssl_bump,
        request.getRaw(), nullptr);
    acl_checklist->al = al;
    acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpNone));
    acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpPeek));
    acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpStare));
    acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpClientFirst));
    acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpServerFirst));
    Security::SessionPointer session(fd_table[serverConn->fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    if (!srvBio->canSplice())
        acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpSplice));
    if (!srvBio->canBump())
        acl_checklist->banAction(Acl::Answer(ACCESS_ALLOWED, Ssl::bumpBump));
    acl_checklist->syncAle(request.getRaw(), nullptr);
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
        bail(new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scForbidden, request.getRaw(), al));
        clientConn->close();
        clientConn = nullptr;
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
        if (sslFinalized() && callback)
            callBack();
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

    // client connection supplies TLS client details and is also used if we
    // need to splice or terminate the client and server connections
    if (!Comm::IsConnOpen(clientConn))
        return false;

    if (ConnStateData *csd = request->clientConnectionManager.valid()) {

        SBuf *hostName = nullptr;

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
            ::Security::ProxyOutgoingConfig.updateSessionOptions(serverSession);

            const bool redirected = request->flags.redirected && ::Config.onoff.redir_rewrites_host;
            const char *sniServer = (!hostName || redirected) ?
                                    request->url.host() :
                                    hostName->c_str();
            if (sniServer)
                setClientSNI(serverSession.get(), sniServer);
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
            const auto errDetail = dynamic_cast<Security::ErrorDetail *>(error ? error->detail.getRaw() : nullptr);
            if (errDetail && errDetail->peerCert())
                serverBump->serverCert.resetAndLock(errDetail->peerCert());
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
            if (!Comm::IsConnOpen(clientConn)) {
                bail(new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al));
                throw TextException("from-client connection gone", Here());
            }
            startTunneling();
        }
    }
}

void
Ssl::PeekingPeerConnector::startTunneling()
{
    // switchToTunnel() drains any already buffered from-server data (rBufData)
    fd_table[serverConn->fd].useDefaultIo();
    // tunnelStartShoveling() drains any buffered from-client data (inBuf)
    fd_table[clientConn->fd].useDefaultIo();

    // TODO: Encapsulate this frequently repeated logic into a method.
    const auto session = fd_table[serverConn->fd].ssl;
    auto b = SSL_get_rbio(session.get());
    auto srvBio = static_cast<Ssl::ServerBio*>(BIO_get_data(b));

    debugs(83, 5, "will tunnel instead of negotiating TLS");
    switchToTunnel(request.getRaw(), clientConn, serverConn, srvBio->rBufData());
    answer().tunneled = true;
    disconnect();
    callBack();
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
Ssl::PeekingPeerConnector::noteNegotiationError(const Security::ErrorDetailPointer &errorDetail)
{
    const int fd = serverConnection()->fd;
    Security::SessionPointer session(fd_table[fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));

    if (srvBio->bumpMode() == Ssl::bumpPeek) {
        auto bypassValidator = false;
        if (srvBio->encryptedCertificates()) {
            // it is pointless to peek at encrypted certificates
            //
            // we currently splice all sessions with encrypted certificates
            // if (const auto spliceEncryptedCertificates = true) {
            bypassValidator = true;
            // } // else fall through to find a matching ssl_bump action (with limited info)
        } else if (srvBio->resumingSession()) {
            // In peek mode, the ClientHello message is forwarded to the server.
            // If the server is resuming a previous (spliced) SSL session with
            // the client, then probably we are here because our local SSL
            // object does not know anything about the session being resumed.
            //
            // we currently splice all resumed sessions
            // if (const auto spliceResumed = true) {
            bypassValidator = true;
            // } // else fall through to find a matching ssl_bump action (with limited info)
        }

        if (bypassValidator) {
            bypassCertValidator();
            checkForPeekAndSpliceMatched(Ssl::bumpSplice);
            return;
        }
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
    // TODO: Add/use a positive "successfully validated server cert" signal
    // instead of relying on the "![presumably_]validation_error && serverCert"
    // signal combo.
    if (!SSL_get_ex_data(session.get(), ssl_ex_index_ssl_error_detail) &&
            (srvBio->bumpMode() == Ssl::bumpPeek  || srvBio->bumpMode() == Ssl::bumpStare) && srvBio->holdWrite()) {
        Security::CertPointer serverCert(SSL_get_peer_certificate(session.get()));
        if (serverCert) {
            debugs(81, 3, "hold TLS write on FD " << fd << " despite " << errorDetail);
            checkForPeekAndSplice();
            return;
        }
    }

    // else call parent noteNegotiationError to produce an error page
    Security::PeerConnector::noteNegotiationError(errorDetail);
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

