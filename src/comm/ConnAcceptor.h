#ifndef SQUID_COMM_CONNACCEPTOR_H
#define SQUID_COMM_CONNACCEPTOR_H

#include "config.h"
#include "CommCalls.h"
#include "comm/comm_err_t.h"
#include "comm/forward.h"

#if HAVE_MAP
#include <map>
#endif

namespace Comm
{

class ConnAcceptor : public AsyncJob
{
private:
    void start();
    bool doneAll() const;
    void swanSong();

public:
    ConnAcceptor(int fd, bool accept_many); // Legacy verion that uses new subscribe API.
    ConnAcceptor(Comm::ConnectionPointer &conn, bool accept_many, const char *note);
    ConnAcceptor(const ConnAcceptor &r); // not implemented.
    ~ConnAcceptor();

    /** Subscribe a handler to receive calls back about new connections.
     * Replaces any existing subscribed handler.
     */
    void subscribe(int level, int section, const char *name, CommAcceptCbPtrFun *dialer);

    /** Subscribe a handler to receive calls back about new connections.
     * Replaces any existing subscribed handler.
     * Due to not being able to re-use calls, only permits one to be received.
     */
    void subscribe(const AsyncCall::Pointer &call);

    /** Remove the currently waiting callback subscription.
     * Pending calls will remain scheduled.
     */
    void unsubscribe();

    /** Try and accept another connection (synchronous).
     * If one is pending already the subscribed callback handler will be scheduled
     * to handle it before this method returns.
     */
    void acceptNext();

    /// Call the subscribed callback handler with details about a new connection.
    void notify(int newfd, comm_err_t flag, const Comm::ConnectionPointer &details);

    /// conn being listened on for new connections
    /// Reserved for read-only use.
    ConnectionPointer conn;

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

    /// whether this socket is delayed and on the AcceptLimiter queue.
    /// Reserved for read-only use outside of AcceptLimiter
    int32_t isLimited;

private:
    int callSection;                ///< debug section for subscribed callback.
    int callLevel;                  ///< debug level for subscribed callback.
    char *callName;                 ///< Name for the subscribed callback.
    CommAcceptCbPtrFun *callDialer; ///< dialer to make the subscribed callback

    AsyncCall::Pointer theCallback; // TODO remove legacy pointer. Store dialer of members instead.

private:
    /// Method to test if there are enough file descriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Method callback for whenever an FD is ready to accept a client connection.
    static void doAccept(int fd, void *data);

    void acceptOne();
    int oldAccept(Comm::Connection &details);

    bool mayAcceptMore;

    void setListen();

    CBDATA_CLASS2(ConnAcceptor);
};

}; // namespace Comm

#endif /* SQUID_COMM_CONNACCEPTOR_H */
