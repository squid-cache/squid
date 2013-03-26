#ifndef SQUID_COMM_TCPACCEPTOR_H
#define SQUID_COMM_TCPACCEPTOR_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "base/Subscription.h"
#include "comm_err_t.h"
#include "comm/forward.h"

namespace Comm
{

class AcceptLimiter;

/**
 * Listens on a Comm::Connection for new incoming connections and
 * emits an active Comm::Connection descriptor for the new client.
 *
 * Handles all event limiting required to quash inbound connection
 * floods within the global FD limits of available Squid_MaxFD and
 * client_ip_max_connections.
 *
 * Fills the emitted connection with all connection details able to
 * be looked up. Currently these are the local/remote IP:port details
 * and the listening socket transparent-mode flag.
 */
class TcpAcceptor : public AsyncJob
{
public:
    typedef CbcPointer<Comm::TcpAcceptor> Pointer;

private:
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    TcpAcceptor(const TcpAcceptor &); // not implemented.

public:
    TcpAcceptor(const Comm::ConnectionPointer &conn, const char *note, const Subscription::Pointer &aSub);

    /** Subscribe a handler to receive calls back about new connections.
     * Unsubscribes any existing subscribed handler.
     */
    void subscribe(const Subscription::Pointer &aSub);

    /** Remove the currently waiting callback subscription.
     * Already scheduled callbacks remain scheduled.
     */
    void unsubscribe(const char *reason);

    /** Try and accept another connection (synchronous).
     * If one is pending already the subscribed callback handler will be scheduled
     * to handle it before this method returns.
     */
    void acceptNext();

    /// Call the subscribed callback handler with details about a new connection.
    void notify(const comm_err_t flag, const Comm::ConnectionPointer &details) const;

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

protected:
    friend class AcceptLimiter;
    int32_t isLimited;                   ///< whether this socket is delayed and on the AcceptLimiter queue.

private:
    Subscription::Pointer theCallSub;    ///< used to generate AsyncCalls handling our events.

    /// conn being listened on for new connections
    /// Reserved for read-only use.
    ConnectionPointer conn;

    /// Method to test if there are enough file descriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Method callback for whenever an FD is ready to accept a client connection.
    static void doAccept(int fd, void *data);

    void acceptOne();
    comm_err_t oldAccept(Comm::ConnectionPointer &details);
    void setListen();

    CBDATA_CLASS2(TcpAcceptor);
};

} // namespace Comm

#endif /* SQUID_COMM_TCPACCEPTOR_H */
