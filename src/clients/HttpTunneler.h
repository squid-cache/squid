/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTS_HTTP_TUNNELER_H
#define SQUID_SRC_CLIENTS_HTTP_TUNNELER_H

#include "base/AsyncCbdataCalls.h"
#include "base/AsyncJob.h"
#include "CommCalls.h"
#include "http/forward.h"
#include "clients/forward.h"

class ErrorState;
class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

namespace Http
{

// TODO: Reformat description using Doxygen.

// Establishes an HTTP CONNECT tunnel through another proxy.
//
// The caller receives a call back with Http::TunnelerAnswer.
//
// The caller must monitor the connection for closure because this job will not
// inform the caller about such events.
//
// This job never closes the connection, even on errors. If a 3rd-party closes
// the connection, this job simply quits without informing the caller.
class Tunneler: virtual public AsyncJob
{
    CBDATA_CLASS(Tunneler);

public:
    /// Callback dialer API to allow Tunneler to set the answer.
    class CbDialer
    {
    public:
        virtual ~CbDialer() {}
        /// gives Tunneler access to the in-dialer answer
        virtual Http::TunnelerAnswer &answer() = 0;
    };

public:
    explicit Tunneler(AsyncCall::Pointer &aCallback);
    Tunneler(const Tunneler &) = delete;
    Tunneler &operator =(const Tunneler &) = delete;

    /* configuration; too many fields to use constructor parameters */
    HttpRequestPointer request; ///< peer connection trigger or cause
    Comm::ConnectionPointer connection; ///< TCP connection to peer or origin
    AccessLogEntryPointer al; ///< info for the future access.log entry
    AsyncCall::Pointer callback; ///< we call this with the results
    SBuf url; ///< request-target for the CONNECT request
    time_t lifetimeLimit; ///< do not run longer than this

protected:
    /* AsyncJob API */
    virtual ~Tunneler();
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    void handleConnectionClosure(const CommCloseCbParams&);
    void watchForClosures();
    void setReadTimeout();
    void handleException(const std::exception&);
    void startReadingResponse();
    void writeRequest();
    void handleWrittenRequest(const CommIoCbParams&);
    void handleReadyRead(const CommIoCbParams&);
    void readMore();
    void handleResponse(const bool eof);
    void bailOnResponseError(const char *error, const size_t peerResponseSize);
    void bailWith(ErrorState*);
    void callBack();

    TunnelerAnswer &answer();

private:
    AsyncCall::Pointer writer; ///< called when the request has been written
    AsyncCall::Pointer reader; ///< called when the response should be read
    AsyncCall::Pointer closer; ///< called when the connection is being closed

    SBuf readBuf; ///< either unparsed response or post-response bytes

    const time_t startTime; ///< when the tunnel establishment started

    size_t len; // XXX: Delay ID needs something like this?

    bool requestWritten; ///< whether we successfully wrote the request
    bool tunnelEstablished; ///< whether we got a 200 OK response
};

} // namespace Http

#endif /* SQUID_SRC_CLIENTS_HTTP_TUNNELER_H */
