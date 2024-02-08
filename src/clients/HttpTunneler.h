/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTS_HTTPTUNNELER_H
#define SQUID_SRC_CLIENTS_HTTPTUNNELER_H

#include "base/AsyncCallbacks.h"
#include "base/AsyncJob.h"
#include "clients/forward.h"
#include "clients/HttpTunnelerAnswer.h"
#include "CommCalls.h"
#if USE_DELAY_POOLS
#include "DelayId.h"
#endif
#include "http/forward.h"

class ErrorState;
class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

namespace Http
{

/// Negotiates an HTTP CONNECT tunnel through a forward proxy using a given
/// (open and, if needed, encrypted) TCP connection to that proxy. Owns the
/// connection during these negotiations. The caller receives TunnelerAnswer.
class Tunneler: virtual public AsyncJob
{
    CBDATA_CHILD(Tunneler);

public:
    using Answer = TunnelerAnswer;

    Tunneler(const Comm::ConnectionPointer &, const HttpRequestPointer &, const AsyncCallback<Answer> &, time_t timeout, const AccessLogEntryPointer &);
    Tunneler(const Tunneler &) = delete;
    Tunneler &operator =(const Tunneler &) = delete;

#if USE_DELAY_POOLS
    void setDelayId(DelayId delay_id) {delayId = delay_id;}
#endif

    /// hack: whether the connection requires fwdPconnPool->noteUses()
    bool noteFwdPconnUse;

protected:
    /* AsyncJob API */
    ~Tunneler() override;
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

    void handleConnectionClosure(const CommCloseCbParams&);
    void watchForClosures();
    void handleTimeout(const CommTimeoutCbParams &);
    void startReadingResponse();
    void writeRequest();
    void handleWrittenRequest(const CommIoCbParams&);
    void handleReadyRead(const CommIoCbParams&);
    void readMore();
    void handleResponse(const bool eof);
    void bailOnResponseError(const char *error, HttpReply *);

private:
    /// sends the given error to the initiator
    void bailWith(ErrorState*);

    /// sends the ready-to-use tunnel to the initiator
    void sendSuccess();

    /// a bailWith(), sendSuccess() helper: sends results to the initiator
    void callBack();

    /// stops monitoring the connection
    void disconnect();

    /// updates connection usage history before the connection is closed
    void countFailingConnection(const ErrorState *);

    AsyncCall::Pointer writer; ///< called when the request has been written
    AsyncCall::Pointer reader; ///< called when the response should be read
    AsyncCall::Pointer closer; ///< called when the connection is being closed

    Comm::ConnectionPointer connection; ///< TCP connection to the cache_peer
    HttpRequestPointer request; ///< peer connection trigger or cause
    AsyncCallback<Answer> callback; ///< answer destination
    SBuf url; ///< request-target for the CONNECT request
    time_t lifetimeLimit; ///< do not run longer than this
    AccessLogEntryPointer al; ///< info for the future access.log entry
#if USE_DELAY_POOLS
    DelayId delayId;
#endif

    SBuf readBuf; ///< either unparsed response or post-response bytes
    /// Parser being used at present to parse the HTTP peer response.
    Http1::ResponseParserPointer hp;

    const time_t startTime; ///< when the tunnel establishment started

    bool requestWritten; ///< whether we successfully wrote the request
    bool tunnelEstablished; ///< whether we got a 200 OK response
};

} // namespace Http

#endif /* SQUID_SRC_CLIENTS_HTTPTUNNELER_H */

