#ifndef _SQUID_SRC_COMM_OPENERSTATEDATA_H
#define _SQUID_SRC_COMM_OPENERSTATEDATA_H

#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "cbdata.h"
#include "CommCalls.h"
#include "comm_err_t.h"
#include "comm/forward.h"

namespace Comm
{

/**
 * Async-opener of a Comm connection.
 */
class ConnOpener : public AsyncJob
{
protected:
    virtual void start();
    virtual void swanSong();

public:
    void noteAbort() { mustStop("externally aborted"); }

    typedef CbcPointer<ConnOpener> Pointer;

    virtual bool doneAll() const;

    ConnOpener(Comm::ConnectionPointer &, AsyncCall::Pointer &handler, time_t connect_timeout);
    ~ConnOpener();

    void setHost(const char *);    ///< set the hostname note for this connection
    const char * getHost() const;  ///< get the hostname noted for this connection

private:
    // Undefined because two openers cannot share a connection
    ConnOpener(const ConnOpener &);
    ConnOpener & operator =(const ConnOpener &c);

    void earlyAbort(const CommCloseCbParams &);
    void timeout(const CommTimeoutCbParams &);
    void doneConnecting(comm_err_t status, int xerrno);
    static void InProgressConnectRetry(int fd, void *data);
    static void DelayedConnectRetry(void *data);
    void connect();
    void connected();
    void lookupLocalAddress();

private:
    char *host_;                         ///< domain name we are trying to connect to.
    int temporaryFd_;                    ///< the FD being opened. Do NOT set conn_->fd until it is fully open.
    Comm::ConnectionPointer conn_;       ///< single connection currently to be opened.
    AsyncCall::Pointer callback_;        ///< handler to be called on connection completion.

    int totalTries_;   ///< total number of connection attempts over all destinations so far.
    int failRetries_;  ///< number of retries current destination has been tried.

    /**
     * time at which to abandon the connection.
     * the connection-done callback will be passed COMM_TIMEOUT
     */
    time_t connectTimeout_;

    /// time at which this series of connection attempts was started.
    time_t connectStart_;

    /// handles to calls which we may need to cancel.
    struct Calls {
        AsyncCall::Pointer earlyAbort_;
        AsyncCall::Pointer timeout_;
    } calls_;

    CBDATA_CLASS2(ConnOpener);
};

}; // namespace Comm

#endif /* _SQUID_SRC_COMM_CONNOPENER_H */
