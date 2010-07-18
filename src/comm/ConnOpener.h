#ifndef _SQUID_SRC_COMM_OPENERSTATEDATA_H
#define _SQUID_SRC_COMM_OPENERSTATEDATA_H

#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "cbdata.h"
#include "CommCalls.h"
#include "comm/comm_err_t.h"
#include "comm/forward.h"

namespace Comm {

/**
 * Async-opener of a Comm connection.
 */
class ConnOpener : public AsyncJob
{
public:
    // ****** AsynJob API implementation ******

    /** Actual start opening a TCP connection. */
    void start();

    virtual bool doneAll() const;
    virtual void swanSong();

public:
    // ****** ConnOpener API iplementation ******

    /** attempt to open a connection. */
    ConnOpener(Comm::ConnectionPointer &, AsyncCall::Pointer &handler, time_t connect_timeout);
    ~ConnOpener();

    void setHost(const char *);    ///< set the hostname note for this connection
    const char * getHost() const;  ///< get the hostname noted for this connection

private:
    /* These objects may NOT be created without connections to act on. Do not define this operator. */
    ConnOpener(const ConnOpener &);
    /* These objects may NOT be copied. Do not define this operator. */
    ConnOpener operator =(const ConnOpener &c);

    /** Make an FD connection attempt.
     * Handles the case(s) when a partially setup connection gets closed early.
     */
    void connect(const CommConnectCbParams &unused);

    /** Abort connection attempt.
     * Handles the case(s) when a partially setup connection gets closed early.
     */
    void earlyAbort(const CommConnectCbParams &);

    /**
     * Handles the case(s) when a partially setup connection gets timed out.
     * NP: When commSetTimeout accepts generic CommCommonCbParams this can die.
     */
    void timeout(const CommTimeoutCbParams &unused);

    /**
     * Connection attempt are completed. One way or the other.
     * Pass the results back to the external handler.
     */
    void callCallback(comm_err_t status, int xerrno);

    // Legacy Wrapper for the retry event after COMM_INPROGRESS
    // As soon as comm IO accepts Async calls we can use a ConnOpener::connect call
    static void ConnectRetry(int fd, void *data);

private:
    /**
     * time at which to abandon the connection.
     * the connection-done callback will be passed COMM_TIMEOUT
     */
    time_t connect_timeout;

    char *host;                         ///< domain name we are trying to connect to.

    Comm::ConnectionPointer solo;       ///< single connection currently being opened.
    AsyncCall::Pointer callback;        ///< handler to be called on connection completion.

    int total_tries;   ///< total number of connection attempts over all destinations so far.
    int fail_retries;  ///< number of retries current destination has been tried.
    time_t connstart;  ///< time at which this series of connection attempts was started.

    /// handles to calls which we may need to cancel.
    struct _calls {
        AsyncCall::Pointer earlyabort;
        AsyncCall::Pointer timeout;
    } calls;

    CBDATA_CLASS2(ConnOpener);
};

}; // namespace Comm

#endif /* _SQUID_SRC_COMM_CONNOPENER_H */
