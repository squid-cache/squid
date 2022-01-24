/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPXACTION_H
#define SQUID_ICAPXACTION_H

#include "AccessLogEntry.h"
#include "adaptation/icap/ServiceRep.h"
#include "adaptation/Initiate.h"
#include "base/JobWait.h"
#include "comm/ConnOpener.h"
#include "error/forward.h"
#include "HttpReply.h"
#include "ipcache.h"
#include "sbuf/SBuf.h"

class MemBuf;

namespace Ssl {
class IcapPeerConnector;
}

namespace Adaptation
{
namespace Icap
{

/*
 * The ICAP Xaction implements common tasks for ICAP OPTIONS, REQMOD, and
 * RESPMOD transactions. It is started by an Initiator. It terminates
 * on its own, when done. Transactions communicate with Initiator using
 * asynchronous messages because a transaction or Initiator may be gone at
 * any time.
 */

// Note: Xaction must be the first parent for object-unaware cbdata to work

class Xaction: public Adaptation::Initiate
{

public:
    Xaction(const char *aTypeName, ServiceRep::Pointer &aService);
    virtual ~Xaction();

    void disableRetries();
    void disableRepeats(const char *reason);
    bool retriable() const { return isRetriable; }
    bool repeatable() const { return isRepeatable; }

    // comm handler wrappers, treat as private
    void noteCommConnected(const CommConnectCbParams &io);
    void noteCommWrote(const CommIoCbParams &io);
    void noteCommRead(const CommIoCbParams &io);
    void noteCommTimedout(const CommTimeoutCbParams &io);
    void noteCommClosed(const CommCloseCbParams &io);

    // TODO: create these only when actually sending/receiving
    HttpRequest *icapRequest; ///< sent (or at least created) ICAP request
    HttpReply::Pointer icapReply; ///< received ICAP reply, if any

    /// the number of times we tried to get to the service, including this time
    int attempts;

protected:
    virtual void start();
    virtual void noteInitiatorAborted(); // TODO: move to Adaptation::Initiate

    /// starts sending/receiving ICAP messages
    virtual void startShoveling() = 0;

    // comm hanndlers; called by comm handler wrappers
    virtual void handleCommWrote(size_t sz) = 0;
    virtual void handleCommRead(size_t sz) = 0;

    void handleSecuredPeer(Security::EncryptorAnswer &answer);
    /// record error detail if possible
    virtual void detailError(const ErrorDetailPointer &) {}

    void openConnection();
    void closeConnection();
    bool haveConnection() const;

    void scheduleRead();
    void scheduleWrite(MemBuf &buf);
    void updateTimeout();

    void cancelRead();

    bool parseHttpMsg(Http::Message *msg); // true=success; false=needMore; throw=err
    bool mayReadMore() const;

    virtual bool doneReading() const;
    virtual bool doneWriting() const;
    bool doneWithIo() const;
    virtual bool doneAll() const;

    // called just before the 'done' transaction is deleted
    virtual void swanSong();

    // returns a temporary string depicting transaction status, for debugging
    virtual const char *status() const;
    virtual void fillPendingStatus(MemBuf &buf) const;
    virtual void fillDoneStatus(MemBuf &buf) const;

    // useful for debugging
    virtual bool fillVirginHttpHeader(MemBuf&) const;

public:
    // custom exception handling and end-of-call checks
    virtual void callException(const std::exception  &e);
    virtual void callEnd();
    /// clear stored error details, if any; used for retries/repeats
    virtual void clearError() {}
    virtual AccessLogEntry::Pointer masterLogEntry();
    void dnsLookupDone(const ipcache_addrs *ia);

protected:
    // logging
    void setOutcome(const XactOutcome &xo);
    virtual void finalizeLogInfo();

public:
    ServiceRep &service();

private:
    void useTransportConnection(const Comm::ConnectionPointer &);
    void useIcapConnection(const Comm::ConnectionPointer &);
    void dieOnConnectionFailure();
    void tellQueryAborted();
    void maybeLog();

protected:
    Adaptation::Icap::ServiceRep::Pointer theService;

    SBuf readBuf;
    bool commEof;
    bool reuseConnection;
    bool isRetriable;  ///< can retry on persistent connection failures
    bool isRepeatable; ///< can repeat if no or unsatisfactory response
    bool ignoreLastWrite;
    bool waitingForDns; ///< expecting a ipcache_nbgethostbyname() callback

    AsyncCall::Pointer reader;
    AsyncCall::Pointer writer;

    AccessLogEntry::Pointer alep; ///< icap.log entry
    AccessLogEntry &al; ///< short for *alep

    timeval icap_tr_start;     /*time when the ICAP transaction was created */
    timeval icap_tio_start;    /*time when the first ICAP request byte was scheduled for sending*/
    timeval icap_tio_finish;   /*time when the last byte of the ICAP responsewas received*/

private:
    /// waits for a transport connection to the ICAP server to be established/opened
    JobWait<Comm::ConnOpener> transportWait;

    /// waits for the established transport connection to be secured/encrypted
    JobWait<Ssl::IcapPeerConnector> encryptionWait;

    /// open and, if necessary, secured connection to the ICAP server (or nil)
    Comm::ConnectionPointer connection;

    AsyncCall::Pointer closer;
};

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPXACTION_H */

