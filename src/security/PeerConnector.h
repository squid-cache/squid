/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_PEERCONNECTOR_H
#define SQUID_SRC_SECURITY_PEERCONNECTOR_H

#include "acl/Acl.h"
#include "base/AsyncCbdataCalls.h"
#include "base/AsyncJob.h"
#include "CommCalls.h"
#include "http/forward.h"
#include "security/EncryptorAnswer.h"
#include "security/forward.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <iosfwd>
#include <queue>

class ErrorState;
class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

namespace Security
{

class IoResult;
typedef RefCount<IoResult> IoResultPointer;

/**
 * Initiates encryption of a given open TCP connection to a peer or server.
 * Despite its name does not perform any connect(2) operations. Owns the
 * connection during TLS negotiations. The caller receives EncryptorAnswer.
 *
 * Contains common code and interfaces of various specialized PeerConnector's,
 * including peer certificate validation code.
 */
class PeerConnector: virtual public AsyncJob
{
    CBDATA_CLASS(PeerConnector);

public:
    typedef CbcPointer<PeerConnector> Pointer;

    /// Callback dialer API to allow PeerConnector to set the answer.
    class CbDialer
    {
    public:
        virtual ~CbDialer() {}
        /// gives PeerConnector access to the in-dialer answer
        virtual Security::EncryptorAnswer &answer() = 0;
    };

public:
    PeerConnector(const Comm::ConnectionPointer &aServerConn,
                  AsyncCall::Pointer &aCallback,
                  const AccessLogEntryPointer &alp,
                  const time_t timeout = 0);
    virtual ~PeerConnector();

    /// hack: whether the connection requires fwdPconnPool->noteUses()
    bool noteFwdPconnUse;

protected:
    // AsyncJob API
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    /// The connection read timeout callback handler.
    void commTimeoutHandler(const CommTimeoutCbParams &);

    /// The comm_close callback handler.
    void commCloseHandler(const CommCloseCbParams &params);

    /// \returns true on successful TLS session initialization
    virtual bool initialize(Security::SessionPointer &);

    /// Performs a single secure connection negotiation step.
    /// It is called multiple times untill the negotiation finishes or aborts.
    void negotiate();

    /// Called after negotiation has finished. Cleans up TLS/SSL state.
    /// Returns false if we are now waiting for the certs validation job.
    /// Otherwise, returns true, regardless of negotiation success/failure.
    bool sslFinalized();

    /// Called after each negotiation step to handle the result
    void handleNegotiationResult(const Security::IoResult &);

    /// Called when the openSSL SSL_connect fnction request more data from
    /// the remote SSL server. Sets the read timeout and sets the
    /// Squid COMM_SELECT_READ handler.
    void noteWantRead();

    /// Whether TLS negotiation has been paused and not yet resumed
    bool isSuspended() const { return static_cast<bool>(suspendedError_); }

#if USE_OPENSSL
    /// Suspends TLS negotiation to download the missing certificates
    /// \param lastError an error to handle when resuming negotiations
    void suspendNegotiation(const Security::IoResult &lastError);

    /// Resumes TLS negotiation paused by suspendNegotiation()
    void resumeNegotiation();

    /// Either initiates fetching of missing certificates or bails with an error
    void handleMissingCertificates(const Security::IoResult &lastError);

    /// Start downloading procedure for the given URL.
    void startCertDownloading(SBuf &url);

    /// Called by Downloader after a certificate object downloaded.
    void certDownloadingDone(SBuf &object, int status);
#endif

    /// Called when the openSSL SSL_connect function needs to write data to
    /// the remote SSL server. Sets the Squid COMM_SELECT_WRITE handler.
    virtual void noteWantWrite();

    /// Called when the SSL_connect function aborts with an SSL negotiation error
    virtual void noteNegotiationError(const Security::ErrorDetailPointer &);

    /// Called when the SSL negotiation to the server completed and the certificates
    /// validated using the cert validator.
    /// \param error if not NULL the SSL negotiation was aborted with an error
    virtual void noteNegotiationDone(ErrorState *error) {}

    /// Must implemented by the kid classes to return the TLS context object to use
    /// for building the encryption context objects.
    virtual Security::ContextPointer getTlsContext() = 0;

    /// mimics FwdState to minimize changes to FwdState::initiate/negotiateSsl
    Comm::ConnectionPointer const &serverConnection() const { return serverConn; }

    /// sends the given error to the initiator
    void bail(ErrorState *error);

    /// sends the encrypted connection to the initiator
    void sendSuccess();

    /// a bail(), sendSuccess() helper: sends results to the initiator
    void callBack();

    /// a bail(), sendSuccess() helper: stops monitoring the connection
    void disconnect();

    /// If called the certificates validator will not used
    void bypassCertValidator() {useCertValidator_ = false;}

    /// Called after negotiation finishes to record connection details for
    /// logging
    void recordNegotiationDetails();

    HttpRequestPointer request; ///< peer connection trigger or cause
    Comm::ConnectionPointer serverConn; ///< TCP connection to the peer
    AccessLogEntryPointer al; ///< info for the future access.log entry
    AsyncCall::Pointer callback; ///< we call this with the results
private:
    PeerConnector(const PeerConnector &); // not implemented
    PeerConnector &operator =(const PeerConnector &); // not implemented

#if USE_OPENSSL
    unsigned int certDownloadNestingLevel() const;

    /// Process response from cert validator helper
    void sslCrtvdHandleReply(Ssl::CertValidationResponsePointer);

    /// Check SSL errors returned from cert validator against sslproxy_cert_error access list
    Security::CertErrors *sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &, ErrorDetailPointer &);

    bool computeMissingCertificateUrls(const Connection &);
#endif

    static void NegotiateSsl(int fd, void *data);
    void negotiateSsl();

    /// The maximum number of missing certificates a single PeerConnector may download
    static const unsigned int MaxCertsDownloads = 10;

    /// The maximum number of inter-dependent Downloader jobs a worker may initiate
    static const unsigned int MaxNestedDownloads = 3;

    AsyncCall::Pointer closeHandler; ///< we call this when the connection closed
    time_t negotiationTimeout; ///< the SSL connection timeout to use
    time_t startTime; ///< when the peer connector negotiation started
    bool useCertValidator_; ///< whether the certificate validator should bypassed
    /// The list of URLs where missing certificates should be downloaded.
    std::queue<SBuf> urlsOfMissingCerts;
    unsigned int certsDownloads; ///< the number of downloaded missing certificates

#if USE_OPENSSL
    /// successfully downloaded intermediate certificates (omitted by the peer)
    Ssl::X509_STACK_Pointer downloadedCerts;
#endif

    /// outcome of the last (failed and) suspended negotiation attempt (or nil)
    Security::IoResultPointer suspendedError_;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_PEERCONNECTOR_H */

