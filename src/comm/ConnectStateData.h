#ifndef _SQUID_SRC_COMM_CONNECTSTATEDATA_H
#define _SQUID_SRC_COMM_CONNECTSTATEDATA_H

#include "Array.h"
#include "base/AsyncCall.h"
#include "cbdata.h"
#include "comm/comm_err_t.h"
#include "comm/Connection.h"

/**
 * State engine handling the opening of a remote outbound connection
 * to one of multiple destinations.
 */
class ConnectStateData
{
public:
    /** open first working of a set of connections */
    ConnectStateData(Vector<Comm::Connection::Pointer> *paths, AsyncCall::Pointer handler);

    /** attempt to open one connection. */
    ConnectStateData(Comm::Connection::Pointer, AsyncCall::Pointer handler);

    ~ConnectStateData();

    /**
     * Actual connect start function.
     */
    void connect();

private:
    /* These objects may NOT be created without connections to act on. Do not define this operator. */
    ConnectStateData();
    /* These objects may NOT be copied. Do not define this operator. */
    const ConnectStateData operator =(const ConnectStateData &c);

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
     * Connection attempt are completed. One way or the other.
     * Pass the results back to the external handler.
     */
    void callCallback(comm_err_t status, int xerrno);

public:
    char *host;                   ///< domain name we are trying to connect to.

    /**
     * time at which to abandon the connection.
     * the connection-done callback will be passed COMM_TIMEOUT
     */
    time_t connect_timeout;

private:
    Vector<Comm::Connection::Pointer> *paths;  ///< forwarding paths to be tried. front of the list is the current being opened.
    Comm::Connection::Pointer solo;            ///< single connection currently being opened.
    AsyncCall::Pointer callback;               ///< handler to be called on connection completion.

    int total_tries;   ///< total number of connection attempts over all destinations so far.
    int fail_retries;  ///< number of retries current destination has been tried.
    time_t connstart;  ///< time at which this series of connection attempts was started.

    CBDATA_CLASS2(ConnectStateData);
};

#endif /* _SQUID_SRC_COMM_CONNECTSTATEDATA_H */
