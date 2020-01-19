/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTS_HTTP_TUNNELER_H
#define SQUID_SRC_CLIENTS_HTTP_TUNNELER_H

#include "base/AsyncCbdataCalls.h"
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

/// Establishes an HTTP CONNECT tunnel through a forward proxy.
///
/// The caller receives a call back with Http::TunnelerAnswer.
///
/// The caller must monitor the connection for closure because this job will not
/// inform the caller about such events.
///
/// This job never closes the connection, even on errors. If a 3rd-party closes
/// the connection, this job simply quits without informing the caller.
class Tunneler: virtual public AsyncJob
{
    CBDATA_CLASS(Tunneler);

public:
    /// Callback dialer API to allow Tunneler to set the answer.
    template <class Initiator>
    class CbDialer: public CallDialer, public Http::TunnelerAnswer
    {
    public:
        // initiator method to receive our answer
        typedef void (Initiator::*Method)(Http::TunnelerAnswer &);

        CbDialer(Method method, Initiator *initiator): initiator_(initiator), method_(method) {}
        virtual ~CbDialer() = default;

        /* CallDialer API */
        bool canDial(AsyncCall &) { return initiator_.valid(); }
        void dial(AsyncCall &) {((*initiator_).*method_)(*this); }
        virtual void print(std::ostream &os) const override {
            os << '(' << static_cast<const Http::TunnelerAnswer&>(*this) << ')';
        }
    private:
        CbcPointer<Initiator> initiator_; ///< object to deliver the answer to
        Method method_; ///< initiator_ method to call with the answer
    };

public:
    Tunneler(const Comm::ConnectionPointer &conn, const HttpRequestPointer &req, AsyncCall::Pointer &aCallback, time_t timeout, const AccessLogEntryPointer &alp);
    Tunneler(const Tunneler &) = delete;
    Tunneler &operator =(const Tunneler &) = delete;

#if USE_DELAY_POOLS
    void setDelayId(DelayId delay_id) {delayId = delay_id;}
#endif

protected:
    /* AsyncJob API */
    virtual ~Tunneler();
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    void handleConnectionClosure(const CommCloseCbParams&);
    void watchForClosures();
    void handleException(const std::exception&);
    void startReadingResponse();
    void writeRequest();
    void handleWrittenRequest(const CommIoCbParams&);
    void handleReadyRead(const CommIoCbParams&);
    void readMore();
    void handleResponse(const bool eof);
    void bailOnResponseError(const char *error, HttpReply *);
    void bailWith(ErrorState*);
    void callBack();

    TunnelerAnswer &answer();

private:
    AsyncCall::Pointer writer; ///< called when the request has been written
    AsyncCall::Pointer reader; ///< called when the response should be read
    AsyncCall::Pointer closer; ///< called when the connection is being closed

    Comm::ConnectionPointer connection; ///< TCP connection to the cache_peer
    HttpRequestPointer request; ///< peer connection trigger or cause
    AsyncCall::Pointer callback; ///< we call this with the results
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

#endif /* SQUID_SRC_CLIENTS_HTTP_TUNNELER_H */

