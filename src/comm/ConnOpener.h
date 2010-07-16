#ifndef _SQUID_SRC_COMM_OPENERSTATEDATA_H
#define _SQUID_SRC_COMM_OPENERSTATEDATA_H

#include "base/AsyncCall.h"
#include "base/AsyncJob.h"
#include "cbdata.h"
#include "comm/comm_err_t.h"
#include "comm/forward.h"

/**
 * Async-opener of a Comm connection.
 */
class ConnOpener : public AsyncJob
{
public:
    /** attempt to open a connection. */
    ConnOpener(Comm::ConnectionPointer &, AsyncCall::Pointer handler);

    ~ConnOpener();

    /** Actual start opening a TCP connection. */
    void start();

    virtual bool doneAll() const;
private:
    /* These objects may NOT be created without connections to act on. Do not define this operator. */
    ConnOpener(const ConnOpener &);
    /* These objects may NOT be copied. Do not define this operator. */
    ConnOpener operator =(const ConnOpener &c);

    /**
     * Wrapper to start the connection attempts happening.
     */
    static void Connect(void *data);

    /** retry */
    static void ConnectRetry(int fd, void *data);

    /**
     * Temporary close handler used during connect.
     * Handles the case(s) when a partially setup connection gets closed early.
     */
    static void EarlyAbort(int fd, void *data);

    /**
     * Temporary timeout handler used during connect.
     * Handles the case(s) when a partially setup connection gets timed out.
     */
    static void ConnectTimeout(int fd, void *data);

    /**
     * Connection attempt are completed. One way or the other.
     * Pass the results back to the external handler.
     */
    void callCallback(comm_err_t status, int xerrno);

public:
    /**
     * time at which to abandon the connection.
     * the connection-done callback will be passed COMM_TIMEOUT
     */
    time_t connect_timeout;

    void setHost(const char *);        ///< set the hostname note for this connection
    const char * getHost(void) const;  ///< get the hostname noted for this connection

private:
    char *host;                         ///< domain name we are trying to connect to.

    Comm::ConnectionPointer solo;       ///< single connection currently being opened.
    AsyncCall::Pointer callback;        ///< handler to be called on connection completion.

    int total_tries;   ///< total number of connection attempts over all destinations so far.
    int fail_retries;  ///< number of retries current destination has been tried.
    time_t connstart;  ///< time at which this series of connection attempts was started.

    CBDATA_CLASS2(ConnOpener);
};

#endif /* _SQUID_SRC_COMM_CONNOPENER_H */
