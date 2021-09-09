/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_QUIC_ACCEPTOR_H
#define _SQUID__SRC_QUIC_ACCEPTOR_H

#include "anyp/forward.h"
#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "comm/forward.h"
#include "quic/forward.h"
#include "sbuf/forward.h"

class CommCloseCbParams;
class CommIoCbParams;

namespace Quic
{

/**
 * Listens on a Comm::Connection for new incoming QUIC connections and
 * emits an active Server instance to handle the new client.
 */
class Acceptor : public AsyncJob
{
    CBDATA_CLASS(Acceptor);

public:
    typedef CbcPointer<Quic::Acceptor> Pointer;

    Acceptor(const AnyP::PortCfgPointer &);

private:
    /* AsyncJob API */
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    /* ::Server API replicants */
    void readSomeData();
    void doClientRead(const CommIoCbParams &);

    void handleClosure(const CommCloseCbParams &);
    void logAcceptError() const;
    void dispatch(const SBuf &, Ip::Address &);
    void negotiateVersion(Connection &);

    /// errno of the last accept() or listen() action if one occurred.
    int xerrno = 0;

    /// conn being listened on for new connections
    Comm::ConnectionPointer listenConn;

    /// configuration details of the listening port
    AnyP::PortCfgPointer listenPort;

    /// listen socket closure handler
    AsyncCall::Pointer closer;

    /// waiting for a Comm::Read to indicate UDP packets are available
    AsyncCall::Pointer reader;
};

} // namespace Quic

#endif /* _SQUID__SRCC_QUIC_ACCEPTOR_H */

