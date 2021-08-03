/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_CLIENTS_PROXYPROTOCOLCONNECTOR_H
#define SQUID__SRC_CLIENTS_PROXYPROTOCOLCONNECTOR_H

#include "base/AsyncCbdataCalls.h"
#include "base/AsyncJob.h"
#include "clients/forward.h"
#include "clients/HttpTunnelerAnswer.h"
#include "CommCalls.h"
#include "http/forward.h"

class ErrorState;
class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

namespace ProxyProtocol {

/// Generates and delivers PROXYv2 protocol header to a cache_peer proxy
/// using a given TCP connection to that proxy.
class Connector: virtual public AsyncJob
{
    CBDATA_CLASS(Connector);

public:
    Connector(const Comm::ConnectionPointer &, const HttpRequestPointer &, AsyncCall::Pointer &, const AccessLogEntryPointer &);
    Connector(const Connector &) = delete;
    Connector &operator =(const Connector &) = delete;

protected:
    /* AsyncJob API */
    virtual ~Connector();
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

private:
    void watchForClosures();
    void handleConnectionClosure(const CommCloseCbParams &);

    void writeRequest();
    void handleWrittenRequest(const CommIoCbParams &);

    /// sends the given error to the initiator
    void bailWith(ErrorState*);

    /// sends the ready-to-use tunnel to the initiator
    void sendSuccess();

    /// a bailWith(), sendSuccess() helper: sends results to the initiator
    void callBack();

    /// a bailWith(), sendSuccess() helper: stops monitoring the connection
    void disconnect();

    Http::TunnelerAnswer &answer();

private:
    MasterXaction::Pointer xaction; ///< the transaction we are trying to service
    CachePeer *peer = nullptr; ///< the cache_peer we are connecting to
    Comm::ConnectionPointer connection; ///< TCP connection to the cache_peer

    AsyncCall::Pointer writer; ///< called when the PROXY header has been written
    AsyncCall::Pointer closer; ///< called when the connection is being closed

    AsyncCall::Pointer callback; ///< we call this with the results

    // details we only need to pass on to ErrorState
    HttpRequestPointer request;
    AccessLogEntryPointer al;
};

} // namespace ProxyProtocol

#endif /* SQUID__SRC_CLIENTS_PROXYPROTOCOLCONNECTOR_H */

