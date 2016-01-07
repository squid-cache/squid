/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_STREAMCONTEXT_H
#define SQUID_SRC_HTTP_STREAMCONTEXT_H

#include "http/forward.h"
#include "mem/forward.h"
#include "StoreIOBuffer.h"

class clientStreamNode;
class ClientHttpRequest;

namespace Http
{

/**
 * The processing context for a single HTTP transaction (stream).
 *
 * A context lifetime extends from directly after a request has been parsed
 * off the client connection buffer, until the last byte of both request
 * and reply payload (if any) have been written.
 *
 * Contexts self-register with the Http::Server Pipeline being managed by the
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
 * When a context is completed the finished() method needs to be called which
 * will perform all cleanup and deregistration operations. If the reason for
 * finishing is an error, then notifyIoError() needs to be called prior to
 * the finished() method.
 * The caller should follow finished() with a call to ConnStateData::kick()
 * to resume processing of other transactions or I/O on the connection.
 *
 * Alternatively the initiateClose() method can be called to terminate the
 * whole client connection and all other pending contexts.
 *
 * HTTP/1.x:
 *
 * When HTTP/1 pipeline is operating there may be multiple transactions using
 * the client connection. Only the back() context may read from the connection,
 * and only the front() context may write to it. A context which needs to read
 * or write to the connection but does not meet those criteria must be shifted
 * to the deferred state.
 *
 *
 * XXX: If an async call ends the ClientHttpRequest job, Http::StreamContext
 * (and ConnStateData) may not know about it, leading to segfaults and
 * assertions. This is difficult to fix
 * because ClientHttpRequest lacks a good way to communicate its ongoing
 * destruction back to the Http::StreamContext which pretends to "own" *http.
 */
class StreamContext : public RefCountable
{
    MEMPROXY_CLASS(StreamContext);

public:
    /// construct with HTTP/1.x details
    StreamContext(const Comm::ConnectionPointer &aConn, ClientHttpRequest *aReq);
    ~StreamContext();

    bool startOfOutput() const;
    void writeComplete(size_t size);

public: // HTTP/1.x state data

    Comm::ConnectionPointer clientConnection; ///< details about the client connection socket
    ClientHttpRequest *http;    /* we pretend to own that Job */
    HttpReply *reply;
    char reqbuf[HTTP_REQBUF_SZ];
    struct {

        unsigned deferred:1; /* This is a pipelined request waiting for the current object to complete */

        unsigned parsed_ok:1; /* Was this parsed correctly? */
    } flags;
    bool mayUseConnection() const {return mayUseConnection_;}

    void mayUseConnection(bool aBool) {
        mayUseConnection_ = aBool;
        debugs(33,3, HERE << "This " << this << " marked " << aBool);
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

    void pullData();
    int64_t getNextRangeOffset() const;
    bool canPackMoreRanges() const;
    clientStream_status_t socketState();
    void sendBody(HttpReply * rep, StoreIOBuffer bodyData);
    void sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData);
    size_t lengthToSend(Range<int64_t> const &available);
    void noteSentBodyBytes(size_t);
    void buildRangeHeader(HttpReply * rep);
    clientStreamNode * getTail() const;
    clientStreamNode * getClientReplyContext() const;
    ConnStateData *getConn() const;
    void finished(); ///< cleanup when the transaction has finished. may destroy 'this'
    void deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer receivedData);
    bool multipartRangeRequest() const;
    void registerWithConn();
    void noteIoError(const int xerrno); ///< update state to reflect I/O error
    void initiateClose(const char *reason); ///< terminate due to a send/write error (may continue reading)

private:
    void prepareReply(HttpReply * rep);
    void packChunk(const StoreIOBuffer &bodyData, MemBuf &mb);
    void packRange(StoreIOBuffer const &, MemBuf * mb);
    void doClose();

private:
    bool mayUseConnection_; /* This request may use the connection. Don't read anymore requests for now */
    bool connRegistered_;
};

} // namespace Http

#endif /* SQUID_SRC_HTTP_STREAMCONTEXT_H */
