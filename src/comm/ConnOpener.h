/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_COMM_OPENERSTATEDATA_H
#define _SQUID_SRC_COMM_OPENERSTATEDATA_H

#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "cbdata.h"
#include "comm/Flag.h"
#include "comm/forward.h"
#include "CommCalls.h"

namespace Comm
{

/**
 * Async-opener of a Comm connection.
 */
class ConnOpener : public AsyncJob
{
    CBDATA_CLASS(ConnOpener);

public:
    void noteAbort() { mustStop("externally aborted"); }

    typedef CbcPointer<ConnOpener> Pointer;

    virtual bool doneAll() const;

    ConnOpener(Comm::ConnectionPointer &, const AsyncCall::Pointer &handler, time_t connect_timeout);
    ~ConnOpener();

    void setHost(const char *);    ///< set the hostname note for this connection
    const char * getHost() const;  ///< get the hostname noted for this connection

protected:
    virtual void start();
    virtual void swanSong();

private:
    // Undefined because two openers cannot share a connection
    ConnOpener(const ConnOpener &);
    ConnOpener & operator =(const ConnOpener &c);

    void earlyAbort(const CommCloseCbParams &);
    void timeout(const CommTimeoutCbParams &);
    void sendAnswer(Comm::Flag errFlag, int xerrno, const char *why);
    static void InProgressConnectRetry(int fd, void *data);
    static void DelayedConnectRetry(void *data);
    void doConnect();
    void connected();
    void lookupLocalAddress();

    void retrySleep();
    void restart();

    bool createFd();
    void closeFd();
    void keepFd();
    void cleanFd();

    void cancelSleep();

private:
    char *host_;                         ///< domain name we are trying to connect to.
    int temporaryFd_;                    ///< the FD being opened. Do NOT set conn_->fd until it is fully open.
    Comm::ConnectionPointer conn_;       ///< single connection currently to be opened.
    AsyncCall::Pointer callback_;        ///< handler to be called on connection completion.

    int totalTries_;   ///< total number of connection attempts over all destinations so far.
    int failRetries_;  ///< number of retries current destination has been tried.

    /// if we are not done by then, we will call back with Comm::TIMEOUT
    time_t deadline_;

    /// handles to calls which we may need to cancel.
    struct Calls {
        AsyncCall::Pointer earlyAbort_;
        AsyncCall::Pointer timeout_;
        /// Whether we are idling before retrying to connect; not yet a call
        /// [that we can cancel], but it will probably become one eventually.
        bool sleep_;
    } calls_;
};

}; // namespace Comm

#endif /* _SQUID_SRC_COMM_CONNOPENER_H */

