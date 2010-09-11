#ifndef SQUID_COMM_CONNACCEPTOR_H
#define SQUID_COMM_CONNACCEPTOR_H

#include "config.h"
#include "base/Subscription.h"
#include "CommCalls.h"
#include "comm/comm_err_t.h"
#include "comm/forward.h"

#if HAVE_MAP
#include <map>
#endif

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
class ConnAcceptor : public AsyncJob
{
private:
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

public:
    ConnAcceptor(const Comm::ConnectionPointer &conn, const char *note, const Subscription::Pointer &aSub);
    ConnAcceptor(const ConnAcceptor &r); // not implemented.

    /** Subscribe a handler to receive calls back about new connections.
     * Replaces any existing subscribed handler.
     */
    void subscribe(const Subscription::Pointer &aSub);

    /** Remove the currently waiting callback subscription.
     * Pending calls will remain scheduled.
     */
    void unsubscribe(const char *reason);

    /** Try and accept another connection (synchronous).
     * If one is pending already the subscribed callback handler will be scheduled
     * to handle it before this method returns.
     */
    void acceptNext();

    /// Call the subscribed callback handler with details about a new connection.
    void notify(comm_err_t flag, const Comm::ConnectionPointer &details);

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

private:
    friend class AcceptLimiter;
    int32_t isLimited;                   ///< whether this socket is delayed and on the AcceptLimiter queue.
    Subscription::Pointer theCallSub;    ///< used to generate AsyncCalls handling our events.

    /// conn being listened on for new connections
    /// Reserved for read-only use.
    ConnectionPointer conn;

private:
    /// Method to test if there are enough file descriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Method callback for whenever an FD is ready to accept a client connection.
    static void doAccept(int fd, void *data);

    void acceptOne();
    comm_err_t oldAccept(Comm::ConnectionPointer &details);
    void setListen();

    CBDATA_CLASS2(ConnAcceptor);
};

}; // namespace Comm

#endif /* SQUID_COMM_CONNACCEPTOR_H */
