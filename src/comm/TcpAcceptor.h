#ifndef SQUID_COMM_TCPACCEPTOR_H
#define SQUID_COMM_TCPACCEPTOR_H

#include "base/AsyncCall.h"
#include "base/Subscription.h"
#include "CommCalls.h"
#include "comm_err_t.h"
#include "comm/TcpAcceptor.h"
#include "ip/Address.h"

#if HAVE_MAP
#include <map>
#endif

namespace Comm
{

class AcceptLimiter;

/**
 * Listens on an FD for new incoming connections and
 * emits an active FD descriptor for the new client.
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
private:
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    TcpAcceptor(const TcpAcceptor &); // not implemented.

public:
    TcpAcceptor(const int listenFd, const Ip::Address &laddr, int flags,
                const char *note, const Subscription::Pointer &aSub);

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
    void notify(const comm_err_t flags, const ConnectionDetail &newConnDetails, const int newFd) const;

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

    /// conn being listened on for new connections
    /// Reserved for read-only use.
    // NP: public only until we can hide it behind connection handles
    int fd;

protected:
    friend class AcceptLimiter;
    int32_t isLimited;                   ///< whether this socket is delayed and on the AcceptLimiter queue.

private:
    Subscription::Pointer theCallSub;    ///< used to generate AsyncCalls handling our events.

    /// IP Address and port being listened on
    Ip::Address local_addr;

    /// Method to test if there are enough file descriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Method callback for whenever an FD is ready to accept a client connection.
    static void doAccept(int fd, void *data);

    void acceptOne();
    comm_err_t oldAccept(ConnectionDetail &newConnDetails, int *fd);
    void setListen();

    CBDATA_CLASS2(TcpAcceptor);
};

} // namespace Comm

#endif /* SQUID_COMM_TCPACCEPTOR_H */
