/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS Server/Peer negotiation */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "comm/Loops.h"
#include "comm/Read.h"
#include "Downloader.h"
#include "errorpage.h"
#include "fde.h"
#include "FwdState.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "neighbors.h"
#include "pconn.h"
#include "security/Io.h"
#include "security/NegotiationHistory.h"
#include "security/PeerConnector.h"
#include "SquidConfig.h"
#if USE_OPENSSL
#include "ssl/bio.h"
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/helper.h"
#endif

CBDATA_NAMESPACED_CLASS_INIT(Security, PeerConnector);

Security::PeerConnector::PeerConnector(const Comm::ConnectionPointer &aServerConn, AsyncCall::Pointer &aCallback, const AccessLogEntryPointer &alp, const time_t timeout) :
    AsyncJob("Security::PeerConnector"),
    noteFwdPconnUse(false),
    serverConn(aServerConn),
    al(alp),
    callback(aCallback),
    negotiationTimeout(timeout),
    startTime(squid_curtime),
    useCertValidator_(true),
    certsDownloads(0)
{
    debugs(83, 5, serverConn);

    // if this throws, the caller's cb dialer is not our CbDialer
    Must(dynamic_cast<CbDialer*>(callback->getDialer()));

    // watch for external connection closures
    Must(Comm::IsConnOpen(serverConn));
    Must(!fd_table[serverConn->fd].closing());
    typedef CommCbMemFunT<Security::PeerConnector, CommCloseCbParams> Dialer;
    closeHandler = JobCallback(9, 5, Dialer, this, Security::PeerConnector::commCloseHandler);
    comm_add_close_handler(serverConn->fd, closeHandler);
}

bool Security::PeerConnector::doneAll() const
{
    return (!callback || callback->canceled()) && AsyncJob::doneAll();
}

/// Preps connection and SSL state. Calls negotiate().
void
Security::PeerConnector::start()
{
    AsyncJob::start();
    debugs(83, 5, "this=" << (void*)this);

    // we own this Comm::Connection object and its fd exclusively, but must bail
    // if others started closing the socket while we were waiting to start()
    assert(Comm::IsConnOpen(serverConn));
    if (fd_table[serverConn->fd].closing()) {
        bail(new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw(), al));
        return;
    }

    Security::SessionPointer tmp;
    if (initialize(tmp))
        negotiate();
    else
        mustStop("Security::PeerConnector TLS socket initialize failed");
}

void
Security::PeerConnector::commCloseHandler(const CommCloseCbParams &params)
{
    closeHandler = nullptr;

    debugs(83, 5, "FD " << params.fd << ", Security::PeerConnector=" << params.data);
    const auto err = new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scServiceUnavailable, request.getRaw(), al);
#if USE_OPENSSL
    err->detail = new Ssl::ErrorDetail(SQUID_ERR_SSL_HANDSHAKE, nullptr, nullptr);
#endif
    bail(err);
}

void
Security::PeerConnector::commTimeoutHandler(const CommTimeoutCbParams &)
{
    debugs(83, 5, serverConnection() << " timedout. this=" << (void*)this);
    const auto err = new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scGatewayTimeout, request.getRaw(), al);
#if USE_OPENSSL
    err->detail = new Ssl::ErrorDetail(SQUID_ERR_SSL_HANDSHAKE, nullptr, nullptr);
#endif
    bail(err);
}

bool
Security::PeerConnector::initialize(Security::SessionPointer &serverSession)
{
    Security::ContextPointer ctx(getTlsContext());
    debugs(83, 5, serverConnection() << ", ctx=" << (void*)ctx.get());

    if (!ctx || !Security::CreateClientSession(ctx, serverConnection(), "server https start")) {
        const auto xerrno = errno;
        if (!ctx) {
            debugs(83, DBG_IMPORTANT, "Error initializing TLS connection: No security context.");
        } // else CreateClientSession() did the appropriate debugs() already
        const auto anErr = new ErrorState(ERR_SOCKET_FAILURE, Http::scInternalServerError, request.getRaw(), al);
        anErr->xerrno = xerrno;
        noteNegotiationDone(anErr);
        bail(anErr);
        return false;
    }

    // A TLS/SSL session has now been created for the connection and stored in fd_table
    serverSession = fd_table[serverConnection()->fd].ssl;
    debugs(83, 5, serverConnection() << ", session=" << (void*)serverSession.get());

#if USE_OPENSSL
    // If CertValidation Helper used do not lookup checklist for errors,
    // but keep a list of errors to send it to CertValidator
    if (!Ssl::TheConfig.ssl_crt_validator) {
        // Create the ACL check list now, while we have access to more info.
        // The list is used in ssl_verify_cb() and is freed in ssl_free().
        if (acl_access *acl = ::Config.ssl_client.cert_error) {
            ACLFilledChecklist *check = new ACLFilledChecklist(acl, request.getRaw(), dash_str);
            check->al = al;
            check->syncAle(request.getRaw(), nullptr);
            // check->fd(fd); XXX: need client FD here
            SSL_set_ex_data(serverSession.get(), ssl_ex_index_cert_error_check, check);
        }
    }
#endif

    return true;
}

void
Security::PeerConnector::recordNegotiationDetails()
{
    const int fd = serverConnection()->fd;
    Security::SessionPointer session(fd_table[fd].ssl);

    // retrieve TLS server negotiated information if any
    serverConnection()->tlsNegotiations()->retrieveNegotiatedInfo(session);

#if USE_OPENSSL
    // retrieve TLS parsed extra info
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *bio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    if (const Security::TlsDetails::Pointer &details = bio->receivedHelloDetails())
        serverConnection()->tlsNegotiations()->retrieveParsedInfo(details);
#endif
}

void
Security::PeerConnector::negotiate()
{
    const int fd = serverConnection()->fd;
    if (fd_table[fd].closing())
        return;

    const auto result = Security::Connect(*serverConnection());
    switch (result.category) {
    case Security::IoResult::ioSuccess:
        recordNegotiationDetails();
        if (sslFinalized())
            sendSuccess();
        return; // we may be gone by now

    case Security::IoResult::ioWantRead:
        noteWantRead();
        return;

    case Security::IoResult::ioWantWrite:
        noteWantWrite();
        return;

    case Security::IoResult::ioError:
        break; // fall through to error handling
    }

    // TODO: Honor result.important when working in a reverse proxy role?
    debugs(83, 2, "ERROR: " << result.errorDescription <<
           " while establishing TLS connection on FD: " << fd << result.errorDetail);
    recordNegotiationDetails();
    noteNegotiationError(result.errorDetail);
}

bool
Security::PeerConnector::sslFinalized()
{
#if USE_OPENSSL
    if (Ssl::TheConfig.ssl_crt_validator && useCertValidator_) {
        const int fd = serverConnection()->fd;
        Security::SessionPointer session(fd_table[fd].ssl);

        Ssl::CertValidationRequest validationRequest;
        // WARNING: Currently we do not use any locking for 'errors' member
        // of the Ssl::CertValidationRequest class. In this code the
        // Ssl::CertValidationRequest object used only to pass data to
        // Ssl::CertValidationHelper::submit method.
        validationRequest.ssl = session;
        if (SBuf *dName = (SBuf *)SSL_get_ex_data(session.get(), ssl_ex_index_server))
            validationRequest.domainName = dName->c_str();
        if (Security::CertErrors *errs = static_cast<Security::CertErrors *>(SSL_get_ex_data(session.get(), ssl_ex_index_ssl_errors)))
            // validationRequest disappears on return so no need to cbdataReference
            validationRequest.errors = errs;
        try {
            debugs(83, 5, "Sending SSL certificate for validation to ssl_crtvd.");
            AsyncCall::Pointer call = asyncCall(83,5, "Security::PeerConnector::sslCrtvdHandleReply", Ssl::CertValidationHelper::CbDialer(this, &Security::PeerConnector::sslCrtvdHandleReply, nullptr));
            Ssl::CertValidationHelper::Submit(validationRequest, call);
            return false;
        } catch (const std::exception &e) {
            debugs(83, DBG_IMPORTANT, "ERROR: Failed to compose ssl_crtvd " <<
                   "request for " << validationRequest.domainName <<
                   " certificate: " << e.what() << "; will now block to " <<
                   "validate that certificate.");
            // fall through to do blocking in-process generation.
            const auto anErr = new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al);

            noteNegotiationDone(anErr);
            bail(anErr);
            return true;
        }
    }
#endif

    noteNegotiationDone(NULL);
    return true;
}

#if USE_OPENSSL
void
Security::PeerConnector::sslCrtvdHandleReply(Ssl::CertValidationResponse::Pointer validationResponse)
{
    Must(validationResponse != NULL);

    ErrorDetail::Pointer errDetails;
    bool validatorFailed = false;

    if (Debug::Enabled(83, 5)) {
        Security::SessionPointer ssl(fd_table[serverConnection()->fd].ssl);
        SBuf *server = static_cast<SBuf *>(SSL_get_ex_data(ssl.get(), ssl_ex_index_server));
        debugs(83,5, RawPointer("host", server) << " cert validation result: " << validationResponse->resultCode);
    }

    if (validationResponse->resultCode == ::Helper::Error) {
        if (Security::CertErrors *errs = sslCrtvdCheckForErrors(*validationResponse, errDetails)) {
            Security::SessionPointer session(fd_table[serverConnection()->fd].ssl);
            Security::CertErrors *oldErrs = static_cast<Security::CertErrors*>(SSL_get_ex_data(session.get(), ssl_ex_index_ssl_errors));
            SSL_set_ex_data(session.get(), ssl_ex_index_ssl_errors,  (void *)errs);
            delete oldErrs;
        }
    } else if (validationResponse->resultCode != ::Helper::Okay)
        validatorFailed = true;

    if (!errDetails && !validatorFailed) {
        noteNegotiationDone(NULL);
        sendSuccess();
        return;
    }

    ErrorState *anErr = NULL;
    if (validatorFailed) {
        anErr = new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al);
    }  else {
        anErr =  new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scServiceUnavailable, request.getRaw(), al);
        anErr->detailError(errDetails);
        /*anErr->xerrno= Should preserved*/
    }

    noteNegotiationDone(anErr);
    bail(anErr);
    return;
}
#endif

#if USE_OPENSSL
/// Checks errors in the cert. validator response against sslproxy_cert_error.
/// The first honored error, if any, is returned via errDetails parameter.
/// The method returns all seen errors except SSL_ERROR_NONE as Security::CertErrors.
Security::CertErrors *
Security::PeerConnector::sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &resp, ErrorDetail::Pointer &errDetails)
{
    ACLFilledChecklist *check = NULL;
    Security::SessionPointer session(fd_table[serverConnection()->fd].ssl);

    if (acl_access *acl = ::Config.ssl_client.cert_error) {
        check = new ACLFilledChecklist(acl, request.getRaw(), dash_str);
        check->al = al;
        check->syncAle(request.getRaw(), nullptr);
        check->serverCert.resetWithoutLocking(SSL_get_peer_certificate(session.get()));
    }

    Security::CertErrors *errs = nullptr;
    typedef Ssl::CertValidationResponse::RecvdErrors::const_iterator SVCRECI;
    for (SVCRECI i = resp.errors.begin(); i != resp.errors.end(); ++i) {
        debugs(83, 7, "Error item: " << i->error_no << " " << i->error_reason);

        assert(i->error_no != SSL_ERROR_NONE);

        if (!errDetails) {
            bool allowed = false;
            if (check) {
                check->sslErrors = new Security::CertErrors(Security::CertError(i->error_no, i->cert, i->error_depth));
                if (check->fastCheck().allowed())
                    allowed = true;
            }
            // else the Config.ssl_client.cert_error access list is not defined
            // and the first error will cause the error page

            if (allowed) {
                debugs(83, 3, "bypassing SSL error " << i->error_no << " in " << "buffer");
            } else {
                debugs(83, 5, "confirming SSL error " << i->error_no);
                X509 *brokenCert = i->cert.get();
                Security::CertPointer peerCert(SSL_get_peer_certificate(session.get()));
                const char *aReason = i->error_reason.empty() ? NULL : i->error_reason.c_str();
                errDetails = new Ssl::ErrorDetail(i->error_no, peerCert.get(), brokenCert, aReason);
            }
            if (check) {
                delete check->sslErrors;
                check->sslErrors = NULL;
            }
        }

        if (!errs)
            errs = new Security::CertErrors(Security::CertError(i->error_no, i->cert, i->error_depth));
        else
            errs->push_back_unique(Security::CertError(i->error_no, i->cert, i->error_depth));
    }
    if (check)
        delete check;

    return errs;
}
#endif

/// A wrapper for Comm::SetSelect() notifications.
void
Security::PeerConnector::NegotiateSsl(int, void *data)
{
    const auto pc = static_cast<PeerConnector::Pointer*>(data);
    if (pc->valid())
        (*pc)->negotiateSsl();
    delete pc;
}

/// Comm::SetSelect() callback. Direct calls tickle/resume negotiations.
void
Security::PeerConnector::negotiateSsl()
{
    // Use job calls to add done() checks and other job logic/protections.
    CallJobHere(83, 7, this, Security::PeerConnector, negotiate);
}

void
Security::PeerConnector::noteWantRead()
{
    const int fd = serverConnection()->fd;
    debugs(83, 5, serverConnection());
#if USE_OPENSSL
    Security::SessionPointer session(fd_table[fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    if (srvBio->holdRead()) {
        if (srvBio->gotHello()) {
            if (checkForMissingCertificates())
                return; // Wait to download certificates before proceed.

            srvBio->holdRead(false);
            // schedule a negotiateSSl to allow openSSL parse received data
            negotiateSsl();
            return;
        } else if (srvBio->gotHelloFailed()) {
            srvBio->holdRead(false);
            debugs(83, DBG_IMPORTANT, "Error parsing SSL Server Hello Message on FD " << fd);
            // schedule a negotiateSSl to allow openSSL parse received data
            negotiateSsl();
            return;
        }
    }
#endif

    // read timeout to avoid getting stuck while reading from a silent server
    typedef CommCbMemFunT<Security::PeerConnector, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(83, 5,
                                     TimeoutDialer, this, Security::PeerConnector::commTimeoutHandler);
    const auto timeout = Comm::MortalReadTimeout(startTime, negotiationTimeout);
    commSetConnTimeout(serverConnection(), timeout, timeoutCall);

    Comm::SetSelect(fd, COMM_SELECT_READ, &NegotiateSsl, new Pointer(this), 0);
}

void
Security::PeerConnector::noteWantWrite()
{
    const int fd = serverConnection()->fd;
    debugs(83, 5, serverConnection());
    Comm::SetSelect(fd, COMM_SELECT_WRITE, &NegotiateSsl, new Pointer(this), 0);
    return;
}

void
Security::PeerConnector::noteNegotiationError(const Ssl::ErrorDetail::Pointer &callerDetail)
{
#if USE_OPENSSL
    const auto tlsConnection = fd_table[serverConnection()->fd].ssl.get();

    // find the highest priority detail
    auto primaryDetail = callerDetail;
    if (const auto storedDetailRaw = SSL_get_ex_data(tlsConnection, ssl_ex_index_ssl_error_detail)) {
        const auto &storedDetail = *static_cast<Ssl::ErrorDetail::Pointer*>(storedDetailRaw);
        if (storedDetail->takesPriorityOver(*primaryDetail))
            primaryDetail = storedDetail;
    }

    if (!primaryDetail->peerCert()) {
        if (const auto serverCert = SSL_get_peer_certificate(tlsConnection))
            primaryDetail->absorbPeerCertificate(serverCert);
    }
#endif

    const auto anErr = ErrorState::NewForwarding(ERR_SECURE_CONNECT_FAIL, request, al);
    anErr->xerrno = primaryDetail->sysError();
    anErr->detailError(primaryDetail);
    noteNegotiationDone(anErr);
    bail(anErr);
}

void
Security::PeerConnector::bail(ErrorState *error)
{
    Must(error); // or the recipient will not know there was a problem
    Must(callback != NULL);
    CbDialer *dialer = dynamic_cast<CbDialer*>(callback->getDialer());
    Must(dialer);
    dialer->answer().error = error;

    if (const auto p = serverConnection()->getPeer())
        peerConnectFailed(p);

    callBack();
    disconnect();

    if (noteFwdPconnUse)
        fwdPconnPool->noteUses(fd_table[serverConn->fd].pconn.uses);
    serverConn->close();
    serverConn = nullptr;
}

void
Security::PeerConnector::sendSuccess()
{
    callBack();
    disconnect();
}

void
Security::PeerConnector::disconnect()
{
    if (closeHandler) {
        comm_remove_close_handler(serverConnection()->fd, closeHandler);
        closeHandler = nullptr;
    }

    commUnsetConnTimeout(serverConnection());
}

void
Security::PeerConnector::callBack()
{
    debugs(83, 5, "TLS setup ended for " << serverConnection());

    AsyncCall::Pointer cb = callback;
    // Do this now so that if we throw below, swanSong() assert that we _tried_
    // to call back holds.
    callback = NULL; // this should make done() true
    CbDialer *dialer = dynamic_cast<CbDialer*>(cb->getDialer());
    Must(dialer);
    dialer->answer().conn = serverConnection();
    ScheduleCallHere(cb);
}

void
Security::PeerConnector::swanSong()
{
    // XXX: unregister fd-closure monitoring and CommSetSelect interest, if any
    AsyncJob::swanSong();
    if (callback != NULL) { // paranoid: we have left the caller waiting
        debugs(83, DBG_IMPORTANT, "BUG: Unexpected state while connecting to a cache_peer or origin server");
        const auto anErr = new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al);
        bail(anErr);
        assert(!callback);
        return;
    }
}

const char *
Security::PeerConnector::status() const
{
    static MemBuf buf;
    buf.reset();

    // TODO: redesign AsyncJob::status() API to avoid this
    // id and stop reason reporting duplication.
    buf.append(" [", 2);
    if (stopReason != NULL) {
        buf.append("Stopped, reason:", 16);
        buf.appendf("%s",stopReason);
    }
    if (serverConn != NULL)
        buf.appendf(" FD %d", serverConn->fd);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

#if USE_OPENSSL
/// CallDialer to allow use Downloader objects within PeerConnector class.
class PeerConnectorCertDownloaderDialer: public Downloader::CbDialer
{
public:
    typedef void (Security::PeerConnector::*Method)(SBuf &object, int status);

    PeerConnectorCertDownloaderDialer(Method method, Security::PeerConnector *pc):
        method_(method),
        peerConnector_(pc) {}

    /* CallDialer API */
    virtual bool canDial(AsyncCall &call) { return peerConnector_.valid(); }
    virtual void dial(AsyncCall &call) { ((&(*peerConnector_))->*method_)(object, status); }
    Method method_; ///< The Security::PeerConnector method to dial
    CbcPointer<Security::PeerConnector> peerConnector_; ///< The Security::PeerConnector object
};

void
Security::PeerConnector::startCertDownloading(SBuf &url)
{
    AsyncCall::Pointer certCallback = asyncCall(81, 4,
                                      "Security::PeerConnector::certDownloadingDone",
                                      PeerConnectorCertDownloaderDialer(&Security::PeerConnector::certDownloadingDone, this));

    const Downloader *csd = (request ? dynamic_cast<const Downloader*>(request->downloader.valid()) : nullptr);
    Downloader *dl = new Downloader(url, certCallback, XactionInitiator::initCertFetcher, csd ? csd->nestedLevel() + 1 : 1);
    AsyncJob::Start(dl);
}

void
Security::PeerConnector::certDownloadingDone(SBuf &obj, int downloadStatus)
{
    ++certsDownloads;
    debugs(81, 5, "Certificate downloading status: " << downloadStatus << " certificate size: " << obj.length());

    // get ServerBio from SSL object
    const int fd = serverConnection()->fd;
    Security::SessionPointer session(fd_table[fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));

    // Parse Certificate. Assume that it is in DER format.
    // According to RFC 4325:
    //  The server must provide a DER encoded certificate or a collection
    // collection of certificates in a "certs-only" CMS message.
    //  The applications MUST accept DER encoded certificates and SHOULD
    // be able to accept collection of certificates.
    // TODO: support collection of certificates
    const unsigned char *raw = (const unsigned char*)obj.rawContent();
    if (X509 *cert = d2i_X509(NULL, &raw, obj.length())) {
        char buffer[1024];
        debugs(81, 5, "Retrieved certificate: " << X509_NAME_oneline(X509_get_subject_name(cert), buffer, 1024));
        ContextPointer ctx(getTlsContext());
        const Security::CertList &certsList = srvBio->serverCertificatesIfAny();
        if (const char *issuerUri = Ssl::uriOfIssuerIfMissing(cert, certsList, ctx)) {
            urlsOfMissingCerts.push(SBuf(issuerUri));
        }
        Ssl::SSL_add_untrusted_cert(session.get(), cert);
    }

    // Check if there are URIs to download from and if yes start downloading
    // the first in queue.
    if (urlsOfMissingCerts.size() && certsDownloads <= MaxCertsDownloads) {
        startCertDownloading(urlsOfMissingCerts.front());
        urlsOfMissingCerts.pop();
        return;
    }

    srvBio->holdRead(false);
    negotiateSsl();
}

bool
Security::PeerConnector::checkForMissingCertificates()
{
    // Check for nested SSL certificates downloads. For example when the
    // certificate located in an SSL site which requires to download a
    // a missing certificate (... from an SSL site which requires to ...).

    const Downloader *csd = (request ? request->downloader.get() : nullptr);
    if (csd && csd->nestedLevel() >= MaxNestedDownloads)
        return false;

    const int fd = serverConnection()->fd;
    Security::SessionPointer session(fd_table[fd].ssl);
    BIO *b = SSL_get_rbio(session.get());
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(BIO_get_data(b));
    const Security::CertList &certs = srvBio->serverCertificatesIfAny();

    if (certs.size()) {
        debugs(83, 5, "SSL server sent " << certs.size() << " certificates");
        ContextPointer ctx(getTlsContext());
        Ssl::missingChainCertificatesUrls(urlsOfMissingCerts, certs, ctx);
        if (urlsOfMissingCerts.size()) {
            startCertDownloading(urlsOfMissingCerts.front());
            urlsOfMissingCerts.pop();
            return true;
        }
    }

    return false;
}
#endif //USE_OPENSSL

