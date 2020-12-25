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
#include "security/NegotiationHistory.h"
#include "security/PeerConnector.h"
#include "SquidConfig.h"
#if USE_OPENSSL
#include "ssl/bio.h"
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/helper.h"
#endif

/// XXX: Replace with Security::ErrorDetail (which also handles errno)
/// TLS negotiation error details extracted at the error discovery time
class TlsNegotiationDetails: public RefCountable {
public:
    typedef UnaryMemFunT<Security::PeerConnector, TlsNegotiationDetails> Dialer;

#if USE_OPENSSL || USE_GNUTLS
    TlsNegotiationDetails(int ioResult, const Security::Connection &);
#else
    TlsNegotiationDetails() = default;
#endif

    int sslIoResult = 0; ///< SSL_connect() or gnutls_handshake() return value
    int ssl_error = 0; ///< an error retrieved from SSL_get_error
    unsigned long ssl_lib_error = 0; ///< OpenSSL library error
};

/// TlsNegotiationDetails::Dialer parameter printer
static inline std::ostream &
operator <<(std::ostream &os, const TlsNegotiationDetails &ed)
{
#if USE_OPENSSL
    os << ed.sslIoResult << ", " << ed.ssl_error << ", " << ed.ssl_lib_error;
#elif USE_GNUTLS
    os << ed.sslIoResult;
#endif
    return os;
}

#if USE_OPENSSL || USE_GNUTLS
TlsNegotiationDetails::TlsNegotiationDetails(const int ioResult, const Security::Connection &sconn):
    sslIoResult(ioResult)
{
#if USE_OPENSSL
    ssl_error = SSL_get_error(&sconn, sslIoResult);

    switch (ssl_error) {
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
        ssl_lib_error = ERR_get_error();
        break;
    }
#endif
}
#endif /* USE_OPENSSL || USE_GNUTLS */

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

    // Protect from cycles in the certificate dependency graph: TLS site S1 is
    // missing certificate C1 located at TLS site S2. TLS site S2 is missing
    // certificate C2 located at TLS site [...] S1.
    const auto cycle = certDownloadNestingLevel() >= MaxNestedDownloads;
    if (cycle)
        debugs(83, 3, "will not fetch any missing certificates; suspecting cycle: " << certDownloadNestingLevel() << '/' << MaxNestedDownloads);
    const auto sessData = Ssl::SquidVerifyData::New(*serverSession);
    sessData->callerHandlesMissingCertificates = !cycle;
#endif

    return true;
}

bool
Security::PeerConnector::isSuspended() const
{
#if USE_OPENSSL
    return suspendedError_ != nullptr;
#else
    return false; // we do not suspend negotiations when using other libraries
#endif
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

#if USE_OPENSSL
    auto session = fd_table[fd].ssl.get();
    debugs(83, 5, "SSL_connect session=" << (void*)session);
    Must(session);
    const int result = SSL_connect(session);
    auto &sconn = *session;
    const TlsNegotiationDetails ed(result, sconn);

    // Our handling of X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (abbreviated
    // here as EUNABLE) approximates what would happen if we could (try to)
    // fetch any missing certificate(s) _during_ OpenSSL certificate validation.
    // * We did not hide EUNABLE; SSL_connect() was successful: Handle success.
    // * We did not hide EUNABLE; SSL_connect() reported some error E: Honor E.
    // * We hid EUNABLE; SSL_connect() was successful: Warn and kill the job.
    // * We hid EUNABLE; SSL_connect() reported EUNABLE: Warn but honor EUNABLE.
    // * We hid EUNABLE; SSL_connect() reported some EOTHER: Remember EOTHER and
    //   try to fetch the missing certificates. If all goes well, honor EOTHER.
    //   If fetching or post-fetching validation fails, then honor that failure
    //   because EOTHER would not have happened if we fetched during validation.
    if (auto &missingIssuer = Ssl::SquidVerifyData::At(sconn).missingIssuer) {
        missingIssuer = false; // prep for the next SSL_connect()

        // The result cannot be positive here because successful negotiation
        // (sans X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) requires sending
        // a TLS Finished message, which ought to trigger SSL_ERROR_WANT_WRITE.
        if (result > 0) {
            debugs(83, DBG_IMPORTANT, "BUG: Discarding SSL_connect() success due to X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
            throw TextException("unexpected SSL_connect() success", Here());
        }

        if (ed.ssl_error != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            return handleMissingCertificates(ed);

        debugs(83, DBG_IMPORTANT, "BUG: Honoring unexpected SSL_connect() error: X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
        // fall through to regular error handling
    }

    if (result <= 0) {
#elif USE_GNUTLS
    auto session = fd_table[fd].ssl.get();
    const int result = gnutls_handshake(session);
    debugs(83, 5, "gnutls_handshake session=" << (void*)session << ", result=" << result);
    const TlsNegotiationDetails ed(result, *session);

    if (result == GNUTLS_E_SUCCESS) {
        char *desc = gnutls_session_get_desc(session);
        debugs(83, 2, serverConnection() << " TLS Session info: " << desc);
        gnutls_free(desc);
    }

    if (result != GNUTLS_E_SUCCESS) {
        // debug the TLS session state so far
        auto descIn = gnutls_handshake_get_last_in(session);
        debugs(83, 2, "handshake IN: " << gnutls_handshake_description_get_name(descIn));
        auto descOut = gnutls_handshake_get_last_out(session);
        debugs(83, 2, "handshake OUT: " << gnutls_handshake_description_get_name(descOut));
#else
    const TlsNegotiationDetails ed;
    {
#endif
        handleNegotiateError(ed);
        return; // we might be gone by now
    }

    recordNegotiationDetails();

    if (!sslFinalized())
        return;

    sendSuccess();
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

    Ssl::ErrorDetail *errDetails = NULL;
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
        anErr->detail = errDetails;
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
Security::PeerConnector::sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &resp, Ssl::ErrorDetail *& errDetails)
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
Security::PeerConnector::handleNegotiateError(TlsNegotiationDetails ed)
{
    Must(!isSuspended());

    const int fd = serverConnection()->fd;
    const Security::SessionPointer session(fd_table[fd].ssl);

#if USE_OPENSSL
    switch (ed.ssl_error) {
    case SSL_ERROR_WANT_READ:
        noteWantRead();
        return;

    case SSL_ERROR_WANT_WRITE:
        noteWantWrite();
        return;

    default:
        // no special error handling for all other errors
        break;
    }

#elif USE_GNUTLS
    switch (ed.sslIoResult) {
    case GNUTLS_E_WARNING_ALERT_RECEIVED: {
        auto alert = gnutls_alert_get(session.get());
        debugs(83, DBG_IMPORTANT, "TLS ALERT: " << gnutls_alert_get_name(alert));
    }
    // drop through to next case

    case GNUTLS_E_AGAIN:
    case GNUTLS_E_INTERRUPTED:
        if (gnutls_record_get_direction(session.get()) == 0)
            noteWantRead();
        else
            noteWantWrite();
        return;

    default:
        // no special error handling for all other errors
        break;
    }

#else
    // this avoids unused variable compiler warnings.
    Must(!session);
#endif

    // Log connection details, if any
    recordNegotiationDetails();
    noteNegotiationError(ed.sslIoResult, ed.ssl_error, ed.ssl_lib_error);
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
Security::PeerConnector::noteNegotiationError(const int ret, const int ssl_error, const int ssl_lib_error)
{
#if defined(EPROTO)
    int sysErrNo = EPROTO;
#else
    int sysErrNo = EACCES;
#endif

#if USE_OPENSSL
    // store/report errno when ssl_error is SSL_ERROR_SYSCALL, ssl_lib_error is 0, and ret is -1
    if (ssl_error == SSL_ERROR_SYSCALL && ret == -1 && ssl_lib_error == 0)
        sysErrNo = errno;
#endif
    int xerr = errno;

    const int fd = serverConnection()->fd;
    debugs(83, DBG_IMPORTANT, "ERROR: negotiating TLS on FD " << fd <<
           ": " << Security::ErrorString(ssl_lib_error) << " (" <<
           ssl_error << "/" << ret << "/" << xerr << ")");

    const auto anErr = ErrorState::NewForwarding(ERR_SECURE_CONNECT_FAIL, request, al);
    anErr->xerrno = sysErrNo;

#if USE_OPENSSL
    Security::SessionPointer session(fd_table[fd].ssl);
    Ssl::ErrorDetail *errFromFailure = static_cast<Ssl::ErrorDetail *>(SSL_get_ex_data(session.get(), ssl_ex_index_ssl_error_detail));
    if (errFromFailure != NULL) {
        // The errFromFailure is attached to the ssl object
        // and will be released when ssl object destroyed.
        // Copy errFromFailure to a new Ssl::ErrorDetail object
        anErr->detail = new Ssl::ErrorDetail(*errFromFailure);
    } else {
        // server_cert can be NULL here
        X509 *server_cert = SSL_get_peer_certificate(session.get());
        anErr->detail = new Ssl::ErrorDetail(SQUID_ERR_SSL_HANDSHAKE, server_cert, NULL);
        X509_free(server_cert);
    }

    if (ssl_lib_error != SSL_ERROR_NONE)
        anErr->detail->setLibError(ssl_lib_error);
#endif

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

/// the number of concurrent certificate downloading sessions for our request
unsigned int
Security::PeerConnector::certDownloadNestingLevel() const
{
    if (const auto firstDownloader = (request ? request->downloader.get() : nullptr))
        return firstDownloader->nestedLevel();
    return 0;
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
        ContextPointer ctx(getTlsContext());
        const auto certsList = SSL_get_peer_cert_chain(&sconn);
        if (const char *issuerUri = Ssl::uriOfIssuerIfMissing(cert, certsList, ctx)) {
            urlsOfMissingCerts.push(SBuf(issuerUri));
        }

        if (!downloadedCerts.get())
            downloadedCerts.reset(sk_X509_new_null());
        sk_X509_push(downloadedCerts.get(), cert);
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

// TODO: Rename to startHandlingMissingCertificates to emphasize its async nature
// TODO: Rename runValidationCallouts as well.
/// A call to this function must lead to missingCertificatesRetrieved()!
void
Security::PeerConnector::handleMissingCertificates(const TlsNegotiationDetails &ed)
{
    // paranoid: we also clear callerHandlesMissingCertificates to prevent loops
    Must(!runValidationCallouts);
    runValidationCallouts = true;

    auto &sconn = *fd_table[serverConnection()->fd].ssl;

    // We download the missing certificate(s) once. We would prefer to clear
    // this right after the first validation, but that ideal place is _inside_
    // OpenSSL if validation is triggered by SSL_connect(). That function and
    // our OpenSSL verify_callback function (\ref OpenSSL_vcb_disambiguation)
    // may be called multiple times, so we cannot reset there.
    Ssl::SquidVerifyData::At(sconn).callerHandlesMissingCertificates = false;

    if (!computeMissingCertificates(sconn))
        return handleNegotiateError(ed);

    suspendNegotiation(ed);

    assert(!urlsOfMissingCerts.empty());
    startCertDownloading(urlsOfMissingCerts.front());
    urlsOfMissingCerts.pop();
}

/// calculates URLs of the missing intermediate certificates or returns false
bool
Security::PeerConnector::computeMissingCertificates(const Connection &sconn)
{
    const auto certs = SSL_get_peer_cert_chain(&sconn);
    if (!certs) {
        debugs(83, 3, "nothing to bootstrap the fetch with");
        return false;
    }
    debugs(83, 5, "server certificates: " << sk_X509_num(certs));

    const auto ctx = getTlsContext();
    Ssl::missingChainCertificatesUrls(urlsOfMissingCerts, certs, ctx);
    if (urlsOfMissingCerts.empty()) {
        debugs(83, 3, "found no URLs to fetch the missing certificates from");
        return false;
    }

    debugs(83, 5, "initial URLs to fetch the missing certificates from: " << urlsOfMissingCerts.size());
    return true;
}

void
Security::PeerConnector::suspendNegotiation(const TlsNegotiationDetails &details)
{
    debugs(83, 5, "after " << details);
    Must(!isSuspended());
    suspendedError_ = new TlsNegotiationDetails(details);
    Must(isSuspended());
    // negotiations resume with a resumeNegotiation() call
}

void
Security::PeerConnector::resumeNegotiation()
{
    Must(isSuspended());

    auto lastError = *suspendedError_; // may be reset below
    suspendedError_ = nullptr;

    auto &sconn = *fd_table[serverConnection()->fd].ssl;
    if (!Ssl::PeerCertificatesVerify(sconn, downloadedCerts)) {
        // simulate an earlier SSL_connect() failure with a new error
        // TODO: When we can use Security::ErrorDetail, we should resume with a
        // detailed _validation_ error, not just a generic SSL_ERROR_SSL!
        lastError = TlsNegotiationDetails(SSL_ERROR_SSL, sconn);
    }

    handleNegotiateError(lastError);
}

#endif //USE_OPENSSL

