/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#include "squid.h"
#include "client_side.h"
#include "client_side_request.h"
#include "comm/Write.h"
#include "HttpHeaderTools.h"
#include "profiler/Profiler.h"
#include "servers/forward.h"
#include "SquidConfig.h"
#include "Store.h"

namespace Http
{

/// Manages a connection from an HTTP client.
class Server: public ConnStateData
{
public:
    Server(const MasterXaction::Pointer &xact, const bool beHttpsServer);
    virtual ~Server() {}

    void readSomeHttpData();

protected:
    /* ConnStateData API */
    virtual ClientSocketContext *parseOneRequest(Http::ProtocolVersion &ver);
    virtual void processParsedRequest(ClientSocketContext *context, const Http::ProtocolVersion &ver);
    virtual void handleReply(HttpReply *rep, StoreIOBuffer receivedData);
    virtual bool writeControlMsgAndCall(ClientSocketContext *context, HttpReply *rep, AsyncCall::Pointer &call);
    virtual time_t idleTimeout() const;

    /* BodyPipe API */
    virtual void noteMoreBodySpaceAvailable(BodyPipe::Pointer);
    virtual void noteBodyConsumerAborted(BodyPipe::Pointer);

    /* AsyncJob API */
    virtual void start();

private:
    void processHttpRequest(ClientSocketContext *const context);
    void handleHttpRequestData();

    HttpParser parser_;
    HttpRequestMethod method_; ///< parsed HTTP method

    /// temporary hack to avoid creating a true HttpsServer class
    const bool isHttpsServer;

    CBDATA_CLASS2(Server);
};

} // namespace Http

CBDATA_NAMESPACED_CLASS_INIT(Http, Server);

Http::Server::Server(const MasterXaction::Pointer &xact, bool beHttpsServer):
    AsyncJob("Http::Server"),
    ConnStateData(xact),
    isHttpsServer(beHttpsServer)
{
}

time_t
Http::Server::idleTimeout() const
{
    return Config.Timeout.clientIdlePconn;
}

void
Http::Server::start()
{
    ConnStateData::start();

#if USE_OPENSSL
    // XXX: Until we create an HttpsServer class, use this hack to allow old
    // client_side.cc code to manipulate ConnStateData object directly
    if (isHttpsServer) {
        postHttpsAccept();
        return;
    }
#endif

    typedef CommCbMemFunT<Server, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, this, Http::Server::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.request, timeoutCall);
    readSomeData();
}

void
Http::Server::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    if (!handleRequestBodyData())
        return;

    // too late to read more body
    if (!isOpen() || stoppedReceiving())
        return;

    readSomeData();
}

ClientSocketContext *
Http::Server::parseOneRequest(Http::ProtocolVersion &ver)
{
    ClientSocketContext *context = NULL;
    PROF_start(HttpServer_parseOneRequest);
    HttpParserInit(&parser_, in.buf.c_str(), in.buf.length());
    context = parseHttpRequest(this, &parser_, &method_, &ver);
    PROF_stop(HttpServer_parseOneRequest);
    return context;
}

void
Http::Server::processParsedRequest(ClientSocketContext *context, const Http::ProtocolVersion &ver)
{
    clientProcessRequest(this, &parser_, context, method_, ver);
}

void
Http::Server::noteBodyConsumerAborted(BodyPipe::Pointer ptr)
{
    ConnStateData::noteBodyConsumerAborted(ptr);
    stopReceiving("virgin request body consumer aborted"); // closes ASAP
}

void
Http::Server::handleReply(HttpReply *rep, StoreIOBuffer receivedData)
{
    // the caller guarantees that we are dealing with the current context only
    ClientSocketContext::Pointer context = getCurrentContext();
    Must(context != NULL);
    const ClientHttpRequest *http = context->http;
    Must(http != NULL);

    // After sending Transfer-Encoding: chunked (at least), always send
    // the last-chunk if there was no error, ignoring responseFinishedOrFailed.
    const bool mustSendLastChunk = http->request->flags.chunkedReply &&
                                   !http->request->flags.streamError &&
                                   !EBIT_TEST(http->storeEntry()->flags, ENTRY_BAD_LENGTH) &&
                                   !context->startOfOutput();
    const bool responseFinishedOrFailed = !rep &&
                                          !receivedData.data &&
                                          !receivedData.length;
    if (responseFinishedOrFailed && !mustSendLastChunk) {
        context->writeComplete(context->clientConnection, NULL, 0, Comm::OK);
        return;
    }

    if (!context->startOfOutput()) {
        context->sendBody(rep, receivedData);
        return;
    }

    assert(rep);
    http->al->reply = rep;
    HTTPMSGLOCK(http->al->reply);
    context->sendStartOfMessage(rep, receivedData);
}

bool
Http::Server::writeControlMsgAndCall(ClientSocketContext *context, HttpReply *rep, AsyncCall::Pointer &call)
{
    // Ignore this late control message if we have started sending a
    // reply to the user already (e.g., after an error).
    if (context->reply) {
        debugs(11, 2, "drop 1xx made late by " << context->reply);
        return false;
    }

    // apply selected clientReplyContext::buildReplyHeader() mods
    // it is not clear what headers are required for control messages
    rep->header.removeHopByHopEntries();
    rep->header.putStr(HDR_CONNECTION, "keep-alive");
    httpHdrMangleList(&rep->header, getCurrentContext()->http->request, ROR_REPLY);

    MemBuf *mb = rep->pack();

    debugs(11, 2, "HTTP Client " << clientConnection);
    debugs(11, 2, "HTTP Client CONTROL MSG:\n---------\n" << mb->buf << "\n----------");

    Comm::Write(context->clientConnection, mb, call);

    delete mb;
    return true;
}

ConnStateData *
Http::NewServer(MasterXactionPointer &xact)
{
    return new Server(xact, false);
}

ConnStateData *
Https::NewServer(MasterXactionPointer &xact)
{
    return new Http::Server(xact, true);
}

