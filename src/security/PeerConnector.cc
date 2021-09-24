/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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

Security::PeerConnector::~PeerConnector() = default;

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
    static const auto d = MakeNamedErrorDetail("TLS_CONNECT_CLOSE");
    err->detailError(d);
    bail(err);
}

void
Security::PeerConnector::commTimeoutHandler(const CommTimeoutCbParams &)
{
    debugs(83, 5, serverConnection() << " timedout. this=" << (void*)this);
    const auto err = new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scGatewayTimeout, request.getRaw(), al);
    static const auto d = MakeNamedErrorDetail("TLS_CONNECT_TIMEOUT");
    err->detailError(d);
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

    // Protect from cycles in the certificate dependency graph: TLS site S1 is
    // missing certificate C1 located at TLS site S2. TLS site S2 is missing
    // certificate C2 located at [...] TLS site S1.
    const auto cycle = certDownloadNestingLevel() >= MaxNestedDownloads;
    if (cycle)
        debugs(83, 3, "will not fetch any missing certificates; suspecting cycle: " << certDownloadNestingLevel() << '/' << MaxNestedDownloads);
    const auto sessData = Ssl::VerifyCallbackParameters::New(*serverSession);
    // when suspecting a cycle, break it by not fetching any missing certs
    sessData->callerHandlesMissingCertificates = !cycle;
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

#if USE_OPENSSL
    auto &sconn = *fd_table[fd].ssl;

    // OpenSSL v1 APIs do not allow unthreaded applications like Squid to fetch
    // missing certificates _during_ OpenSSL certificate validation. Our
    // handling of X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (abbreviated
    // here as EUNABLE) approximates what would happen if we did (attempt to)
    // fetch any missing certificates during OpenSSL certificate validation.
    // * We did not hide EUNABLE; SSL_connect() was successful: Handle success.
    // * We did not hide EUNABLE; SSL_connect() reported some error E: Honor E.
    // * We hid EUNABLE; SSL_connect() was successful: Remember success and try
    //   to fetch the missing certificates. If all goes well, honor success.
    // * We hid EUNABLE; SSL_connect() reported EUNABLE: Warn but honor EUNABLE.
    // * We hid EUNABLE; SSL_connect() reported some EOTHER: Remember EOTHER and
    //   try to fetch the missing certificates. If all goes well, honor EOTHER.
    //   If fetching or post-fetching validation fails, then honor that failure
    //   because EOTHER would not have happened if we fetched during validation.
    if (auto &hidMissingIssuer = Ssl::VerifyCallbackParameters::At(sconn).hidMissingIssuer) {
        hidMissingIssuer = false; // prep for the next SSL_connect()

        if (result.category == IoResult::ioSuccess ||
                !(result.errorDetail && result.errorDetail->errorNo() == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY))
            return handleMissingCertificates(result);

        debugs(83, DBG_IMPORTANT, "BUG: Honoring unexpected SSL_connect() error: X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
        // fall through to regular error handling
    }
#endif

    handleNegotiationResult(result);
}

void
Security::PeerConnector::handleNegotiationResult(const Security::IoResult &result)
{
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
           " while establishing TLS connection on FD: " << serverConnection()->fd << result.errorDetail);
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
                const auto &brokenCert = i->cert;
                Security::CertPointer peerCert(SSL_get_peer_certificate(session.get()));
                const char *aReason = i->error_reason.empty() ? NULL : i->error_reason.c_str();
                errDetails = new ErrorDetail(i->error_no, peerCert, brokenCert, aReason);
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
Security::PeerConnector::noteNegotiationError(const Security::ErrorDetailPointer &detail)
{
    const auto anErr = ErrorState::NewForwarding(ERR_SECURE_CONNECT_FAIL, request, al);
    if (detail) {
        anErr->xerrno = detail->sysError();
        anErr->detailError(detail);
    }
    noteNegotiationDone(anErr);
    bail(anErr);
}

void
Security::PeerConnector::bail(ErrorState *error)
{
    Must(error); // or the recepient will not know there was a problem
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

/// the number of concurrent PeerConnector jobs waiting for us
unsigned int
Security::PeerConnector::certDownloadNestingLevel() const
{
    if (request) {
        // Nesting level increases when a PeerConnector (at level L) creates a
        // Downloader (which is assigned level L+1). If we were initiated by
        // such a Downloader, then their nesting level is our nesting level.
        if (const auto previousDownloader = request->downloader.get())
            return previousDownloader->nestedLevel();
    }
    return 0; // no other PeerConnector job waits for us
}

void
Security::PeerConnector::startCertDownloading(SBuf &url)
{
    AsyncCall::Pointer certCallback = asyncCall(81, 4,
                                      "Security::PeerConnector::certDownloadingDone",
                                      PeerConnectorCertDownloaderDialer(&Security::PeerConnector::certDownloadingDone, this));

    const auto dl = new Downloader(url, certCallback, XactionInitiator::initCertFetcher, certDownloadNestingLevel() + 1);
    AsyncJob::Start(dl);
}

void
Security::PeerConnector::certDownloadingDone(SBuf &obj, int downloadStatus)
{
    ++certsDownloads;
    debugs(81, 5, "Certificate downloading status: " << downloadStatus << " certificate size: " << obj.length());

    const auto &sconn = *fd_table[serverConnection()->fd].ssl;

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

        if (!downloadedCerts)
            downloadedCerts.reset(sk_X509_new_null());
        sk_X509_push(downloadedCerts.get(), cert);

        ContextPointer ctx(getTlsContext());
        const auto certsList = SSL_get_peer_cert_chain(&sconn);
        if (!Ssl::findIssuerCertificate(cert, certsList, ctx)) {
            if (const auto issuerUri = Ssl::findIssuerUri(cert)) {
                debugs(81, 5, "certificate " <<
                       X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer)) <<
                       " points to its missing issuer certificate at " << issuerUri);
                urlsOfMissingCerts.push(SBuf(issuerUri));
            } else {
                debugs(81, 3, "found a certificate with no IAI, " <<
                       "signed by a missing issuer certificate:  " <<
                       X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer)));
                // We could short-circuit here, proceeding to chain validation
                // that is likely to fail. Instead, we keep going because we
                // hope that if we find at least one certificate to fetch, it
                // will complete the chain (that contained extra certificates).
            }
        }
    }

    // Check if there are URIs to download from and if yes start downloading
    // the first in queue.
    if (urlsOfMissingCerts.size() && certsDownloads <= MaxCertsDownloads) {
        startCertDownloading(urlsOfMissingCerts.front());
        urlsOfMissingCerts.pop();
        return;
    }

    resumeNegotiation();
}

void
Security::PeerConnector::handleMissingCertificates(const Security::IoResult &ioResult)
{
    auto &sconn = *fd_table[serverConnection()->fd].ssl;

    // We download the missing certificate(s) once. We would prefer to clear
    // this right after the first validation, but that ideal place is _inside_
    // OpenSSL if validation is triggered by SSL_connect(). That function and
    // our OpenSSL verify_callback function (\ref OpenSSL_vcb_disambiguation)
    // may be called multiple times, so we cannot reset there.
    auto &callerHandlesMissingCertificates = Ssl::VerifyCallbackParameters::At(sconn).callerHandlesMissingCertificates;
    Must(callerHandlesMissingCertificates);
    callerHandlesMissingCertificates = false;

    suspendNegotiation(ioResult);

    if (!computeMissingCertificateUrls(sconn))
        return resumeNegotiation();

    assert(!urlsOfMissingCerts.empty());
    startCertDownloading(urlsOfMissingCerts.front());
    urlsOfMissingCerts.pop();
}

/// finds URLs of (some) missing intermediate certificates or returns false
bool
Security::PeerConnector::computeMissingCertificateUrls(const Connection &sconn)
{
    const auto certs = SSL_get_peer_cert_chain(&sconn);
    if (!certs) {
        debugs(83, 3, "nothing to bootstrap the fetch with");
        return false;
    }
    debugs(83, 5, "server certificates: " << sk_X509_num(certs));

    const auto ctx = getTlsContext();
    if (!Ssl::missingChainCertificatesUrls(urlsOfMissingCerts, *certs, ctx))
        return false; // missingChainCertificatesUrls() reports the exact reason

    debugs(83, 5, "URLs: " << urlsOfMissingCerts.size());
    assert(!urlsOfMissingCerts.empty());
    return true;
}

void
Security::PeerConnector::suspendNegotiation(const Security::IoResult &ioResult)
{
    debugs(83, 5, "after " << ioResult);
    Must(!isSuspended());
    suspendedError_ = new Security::IoResult(ioResult);
    Must(isSuspended());
    // negotiations resume with a resumeNegotiation() call
}

void
Security::PeerConnector::resumeNegotiation()
{
    Must(isSuspended());

    auto lastError = suspendedError_; // may be reset below
    suspendedError_ = nullptr;

    auto &sconn = *fd_table[serverConnection()->fd].ssl;
    if (!Ssl::VerifyConnCertificates(sconn, downloadedCerts)) {
        // simulate an earlier SSL_connect() failure with a new error
        // TODO: When we can use Security::ErrorDetail, we should resume with a
        // detailed _validation_ error, not just a generic SSL_ERROR_SSL!
        const ErrorDetail::Pointer errorDetail = new ErrorDetail(SQUID_TLS_ERR_CONNECT, SSL_ERROR_SSL, 0);
        lastError = new Security::IoResult(errorDetail);
    }

    handleNegotiationResult(*lastError);
}

#endif //USE_OPENSSL

