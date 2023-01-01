/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_STREAM_H
#define SQUID_SRC_HTTP_STREAM_H

#include "http/forward.h"
#include "mem/forward.h"
#include "StoreIOBuffer.h"
#if USE_DELAY_POOLS
#include "MessageBucket.h"
#endif

class clientStreamNode;
class ClientHttpRequest;

namespace Http
{

/**
 * The processing context for a single HTTP transaction (stream).
 *
 * A stream lifetime extends from directly after a request has been parsed
 * off the client connection buffer, until the last byte of both request
 * and reply payload (if any) have been written, or it is otherwise
 * explicitly terminated.
 *
 * Streams self-register with the Http::Server Pipeline being managed by the
 * Server for the connection on which the request was received.
 *
 * The socket level management and I/O is done by a Server which owns us.
 * The scope of this objects control over a socket consists of the data
 * buffer received from the Server with an initially unknown length.
 * When that length is known it sets the end boundary of our access to the
 * buffer.
 *
 * The individual processing actions are done by other Jobs which we start.
 *
 * When a stream is completed the finished() method needs to be called which
 * will perform all cleanup and deregistration operations. If the reason for
 * finishing is an error, then notifyIoError() needs to be called prior to
 * the finished() method.
 * The caller should follow finished() with a call to ConnStateData::kick()
 * to resume processing of other transactions or I/O on the connection.
 *
 * Alternatively the initiateClose() method can be called to terminate the
 * whole client connection and all other pending streams.
 *
 * HTTP/1.x:
 *
 * When HTTP/1 pipeline is operating there may be multiple transactions using
 * the client connection. Only the back() stream may read from the connection,
 * and only the front() stream may write to it. A stream which needs to read
 * or write to the connection but does not meet those criteria must be shifted
 * to the deferred state.
 *
 *
 * XXX: If an async call ends the ClientHttpRequest job, Http::Stream
 * (and ConnStateData) may not know about it, leading to segfaults and
 * assertions. This is difficult to fix
 * because ClientHttpRequest lacks a good way to communicate its ongoing
 * destruction back to the Http::Stream which pretends to "own" *http.
 */
class Stream : public RefCountable
{
    MEMPROXY_CLASS(Stream);

public:
    /// construct with HTTP/1.x details
    Stream(const Comm::ConnectionPointer &aConn, ClientHttpRequest *aReq);
    ~Stream();

    /// register this stream with the Server
    void registerWithConn();

    /// whether it is registered with a Server
    bool connRegistered() const {return connRegistered_;};

    /// whether the reply has started being sent
    bool startOfOutput() const;

    /// update stream state after a write, may initiate more I/O
    void writeComplete(size_t size);

    /// get more data to send
    void pullData();

    /// \return true if the HTTP request is for multiple ranges
    bool multipartRangeRequest() const;

    int64_t getNextRangeOffset() const;
    bool canPackMoreRanges() const;
    size_t lengthToSend(Range<int64_t> const &available) const;

    clientStream_status_t socketState();

    /// send an HTTP reply message headers and maybe some initial payload
    void sendStartOfMessage(HttpReply *, StoreIOBuffer bodyData);
    /// send some HTTP reply message payload
    void sendBody(StoreIOBuffer bodyData);
    /// update stream state when N bytes are being sent.
    /// NP: Http1Server bytes actually not sent yet, just packed into a MemBuf ready
    void noteSentBodyBytes(size_t);

    /// add Range headers (if any) to the given HTTP reply message
    void buildRangeHeader(HttpReply *);

    clientStreamNode * getTail() const;
    clientStreamNode * getClientReplyContext() const;

    ConnStateData *getConn() const;

    /// update state to reflect I/O error
    void noteIoError(const Error &, const LogTagsErrors &);

    /// cleanup when the transaction has finished. may destroy 'this'
    void finished();

    /// terminate due to a send/write error (may continue reading)
    void initiateClose(const char *reason);

    void deferRecipientForLater(clientStreamNode *, HttpReply *, StoreIOBuffer receivedData);

public: // HTTP/1.x state data

    Comm::ConnectionPointer clientConnection; ///< details about the client connection socket
    ClientHttpRequest *http;    /* we pretend to own that Job */
    HttpReply *reply;
    char reqbuf[HTTP_REQBUF_SZ];
    struct {
        unsigned deferred:1; ///< This is a pipelined request waiting for the current object to complete
        unsigned parsed_ok:1; ///< Was this parsed correctly?
    } flags;

    bool mayUseConnection() const {return mayUseConnection_;}

    void mayUseConnection(bool aBool) {
        mayUseConnection_ = aBool;
        debugs(33, 3, "This " << this << " marked " << aBool);
    }

    class DeferredParams
    {

    public:
        clientStreamNode *node;
        HttpReply *rep;
        StoreIOBuffer queuedBuffer;
    };

    DeferredParams deferredparams;
    int64_t writtenToSocket;

private:
    void prepareReply(HttpReply *);
    void packChunk(const StoreIOBuffer &bodyData, MemBuf &);
    void packRange(StoreIOBuffer const &, MemBuf *);
    void doClose();

    bool mayUseConnection_; /* This request may use the connection. Don't read anymore requests for now */
    bool connRegistered_;
#if USE_DELAY_POOLS
    MessageBucket::Pointer writeQuotaHandler; ///< response write limiter, if configured
#endif
};

} // namespace Http

#endif /* SQUID_SRC_HTTP_STREAM_H */

