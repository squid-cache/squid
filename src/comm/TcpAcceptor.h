/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_COMM_TCPACCEPTOR_H
#define SQUID_SRC_COMM_TCPACCEPTOR_H

#include "anyp/forward.h"
#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "base/Subscription.h"
#include "comm/Flag.h"
#include "comm/forward.h"
#include "CommCalls.h"

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
    CBDATA_CHILD(TcpAcceptor);

public:
    typedef CbcPointer<Comm::TcpAcceptor> Pointer;

private:
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

    TcpAcceptor(const TcpAcceptor &); // not implemented.

public:
    TcpAcceptor(const Comm::ConnectionPointer &conn, const char *note, const Subscription::Pointer &aSub);
    TcpAcceptor(const AnyP::PortCfgPointer &listenPort, const char *note, const Subscription::Pointer &aSub);

protected:
    /** Subscribe a handler to receive calls back about new connections.
     * Unsubscribes any existing subscribed handler.
     */
    void subscribe(const Subscription::Pointer &aSub);

    /** Remove the currently waiting callback subscription.
     * Already scheduled callbacks remain scheduled.
     */
    void unsubscribe(const char *reason);

    /// Call the subscribed callback handler with details about a new connection.
    void notify(const Comm::Flag flag, const Comm::ConnectionPointer &details) const;

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

    /// Method to test if there are enough file descriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /** Try and accept another connection (synchronous).
     *
     * If one is pending already the subscribed callback handler will be
     * scheduled to handle it before this method returns.
     *
     * If there are not enough FD available to do the accept(2) safely will
     * defer the operation until later when enough sockets become available.
     */
    void acceptOne(const CommIoCbParams &);

    friend class AcceptLimiter;

private:
    Subscription::Pointer theCallSub;    ///< used to generate AsyncCalls handling our events.

    /// conn being listened on for new connections
    /// Reserved for read-only use.
    ConnectionPointer conn;

    /// configuration details of the listening port (if provided)
    AnyP::PortCfgPointer listenPort_;

    /// listen socket closure handler
    AsyncCall::Pointer closer_;

    Comm::Flag oldAccept(Comm::ConnectionPointer &details);
    bool acceptInto(Comm::ConnectionPointer &);
    void setListen();
    void handleClosure(const CommCloseCbParams &io);
    /// whether we are listening on one of the squid.conf *ports
    bool intendedForUserConnections() const { return bool(listenPort_); }
    void logAcceptError(const ConnectionPointer &tcpClient) const;
};

} // namespace Comm

#endif /* SQUID_SRC_COMM_TCPACCEPTOR_H */

