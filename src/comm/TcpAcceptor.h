/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
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
    using Pointer = CbcPointer<Comm::TcpAcceptor>;
    using IoDialer = CommCbMemFunT<Comm::TcpAcceptor, CommIoCbParams>;

    TcpAcceptor(const Comm::ConnectionPointer &, const char *note, const Subscription::Pointer &);
    TcpAcceptor(const AnyP::PortCfgPointer &, const char *note, const Subscription::Pointer &);

protected:
    /// Subscribe a handler to receive calls back about new connections.
    /// Unsubscribes any existing subscribed handler.
    void subscribe(const Subscription::Pointer &);

    /// Remove the currently waiting callback subscription.
    /// Already scheduled callbacks remain scheduled.
    void unsubscribe(const char *reason);

    /// Call the subscribed callback handler with details about a new connection.
    void notify(const Comm::Flag, const Comm::ConnectionPointer &) const;

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

    /// Method to test if there are enough file descriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Accept a new connection now if possible, otherwise defer.
    /// This read handler for the listening socket may also be called directly.
    void acceptOne(const CommIoCbParams &);

    friend class AcceptLimiter;

private:
    TcpAcceptor(const TcpAcceptor &); // not implemented.
    Comm::Flag oldAccept(Comm::ConnectionPointer &);
    bool acceptInto(Comm::ConnectionPointer &);
    void setListen();
    void handleClosure(const CommCloseCbParams &);
    /// whether we are listening on one of the squid.conf *ports
    bool intendedForUserConnections() const { return bool(listenPort_); }
    void logAcceptError(const ConnectionPointer &tcpClient) const;

    /* AsyncJob API */
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

private:
    /// used to generate AsyncCalls handling our events.
    Subscription::Pointer theCallSub;

    /// conn being listened on for new connections
    /// Reserved for read-only use.
    ConnectionPointer conn;

    /// configuration details of the listening port (if provided)
    AnyP::PortCfgPointer listenPort_;

    /// listen socket closure handler
    AsyncCall::Pointer closer_;
};

} // namespace Comm

#endif /* SQUID_SRC_COMM_TCPACCEPTOR_H */

