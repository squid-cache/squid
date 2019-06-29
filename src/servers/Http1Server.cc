/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "comm/Write.h"
#include "http/one/RequestParser.h"
#include "http/Stream.h"
#include "HttpHeaderTools.h"
#include "profiler/Profiler.h"
#include "servers/Http1Server.h"
#include "SquidConfig.h"
#include "Store.h"

CBDATA_NAMESPACED_CLASS_INIT(Http1, Server);

Http::One::Server::Server(const MasterXaction::Pointer &xact, bool beHttpsServer):
    AsyncJob("Http1::Server"),
    ConnStateData(xact),
    isHttpsServer(beHttpsServer)
{
}

time_t
Http::One::Server::idleTimeout() const
{
    return Config.Timeout.clientIdlePconn;
}

void
Http::One::Server::start()
{
    ConnStateData::start();

    // XXX: Until we create an HttpsServer class, use this hack to allow old
    // client_side.cc code to manipulate ConnStateData object directly
    if (isHttpsServer) {
        postHttpsAccept();
        return;
    }

    typedef CommCbMemFunT<Server, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(33, 5,
                                      TimeoutDialer, this, Http1::Server::requestTimeout);
    commSetConnTimeout(clientConnection, Config.Timeout.request_start_timeout, timeoutCall);
    readSomeData();
}

void
Http::One::Server::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    if (!handleRequestBodyData())
        return;

    // too late to read more body
    if (!isOpen() || stoppedReceiving())
        return;

    readSomeData();
}

Http::Stream *
Http::One::Server::parseOneRequest()
{
    PROF_start(HttpServer_parseOneRequest);

    // parser is incremental. Generate new parser state if we,
    // a) do not have one already
    // b) have completed the previous request parsing already
    if (!parser_ || !parser_->needsMoreData())
        parser_ = new Http1::RequestParser(mayTunnelUnsupportedProto());

    /* Process request */
    Http::Stream *context = parseHttpRequest(this, parser_);

    PROF_stop(HttpServer_parseOneRequest);
    return context;
}

void clientProcessRequestFinished(ConnStateData *conn, const HttpRequest::Pointer &request);
bool clientTunnelOnError(ConnStateData *conn, Http::StreamPointer &context, HttpRequest::Pointer &request, const HttpRequestMethod& method, err_type requestError);

bool
Http::One::Server::buildHttpRequest(Http::StreamPointer &context)
{
    HttpRequest::Pointer request;
    ClientHttpRequest *http = context->http;
    if (context->flags.parsed_ok == 0) {
        debugs(33, 2, "Invalid Request");
        // determine which error page templates to use for specific parsing errors
        err_type errPage = ERR_INVALID_REQ;
        switch (parser_->parseStatusCode) {
        case Http::scRequestHeaderFieldsTooLarge:
        // fall through to next case
        case Http::scUriTooLong:
            errPage = ERR_TOO_BIG;
            break;
        case Http::scMethodNotAllowed:
            errPage = ERR_UNSUP_REQ;
            break;
        case Http::scHttpVersionNotSupported:
            errPage = ERR_UNSUP_HTTPVERSION;
            break;
        default:
            if (parser_->method() == METHOD_NONE || parser_->requestUri().length() == 0)
                // no method or url parsed, probably is wrong protocol
                errPage = ERR_PROTOCOL_UNKNOWN;
            // else use default ERR_INVALID_REQ set above.
            break;
        }
        // setReplyToError() requires log_uri
        // must be already initialized via ConnStateData::abortRequestParsing()
        assert(http->log_uri);

        const char * requestErrorBytes = inBuf.c_str();
        if (!clientTunnelOnError(this, context, request, parser_->method(), errPage)) {
            setReplyError(context, request, parser_->method(), errPage, parser_->parseStatusCode, requestErrorBytes);
            // HttpRequest object not build yet, there is no reason to call
            // clientProcessRequestFinished method
        }

        return false;
    }

    // TODO: move URL parse into Http Parser and INVALID_URL into the above parse error handling
    MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initClient);
    mx->tcpClient = clientConnection;
    if ((request = HttpRequest::FromUrl(http->uri, mx, parser_->method())) == NULL) {
        debugs(33, 5, "Invalid URL: " << http->uri);
        // setReplyToError() requires log_uri
        http->setLogUriToRawUri(http->uri, parser_->method());

        const char * requestErrorBytes = inBuf.c_str();
        if (!clientTunnelOnError(this, context, request, parser_->method(), ERR_INVALID_URL)) {
            setReplyError(context, request, parser_->method(), ERR_INVALID_URL, Http::scBadRequest, requestErrorBytes);
            // HttpRequest object not build yet, there is no reason to call
            // clientProcessRequestFinished method
        }
        return false;
    }

    /* RFC 2616 section 10.5.6 : handle unsupported HTTP major versions cleanly. */
    /* We currently only support 0.9, 1.0, 1.1 properly */
    /* TODO: move HTTP-specific processing into servers/HttpServer and such */
    if ( (parser_->messageProtocol().major == 0 && parser_->messageProtocol().minor != 9) ||
            (parser_->messageProtocol().major > 1) ) {

        debugs(33, 5, "Unsupported HTTP version discovered. :\n" << parser_->messageProtocol());
        // setReplyToError() requires log_uri
        http->setLogUriToRawUri(http->uri, parser_->method());

        const char * requestErrorBytes = NULL; //HttpParserHdrBuf(parser_);
        if (!clientTunnelOnError(this, context, request, parser_->method(), ERR_UNSUP_HTTPVERSION)) {
            setReplyError(context, request, parser_->method(), ERR_UNSUP_HTTPVERSION, Http::scHttpVersionNotSupported, requestErrorBytes);
            clientProcessRequestFinished(this, request);
        }
        return false;
    }

    /* compile headers */
    if (parser_->messageProtocol().major >= 1 && !request->parseHeader(*parser_.getRaw())) {
        debugs(33, 5, "Failed to parse request headers:\n" << parser_->mimeHeader());
        // setReplyToError() requires log_uri
        http->setLogUriToRawUri(http->uri, parser_->method());
        const char * requestErrorBytes = NULL; //HttpParserHdrBuf(parser_);
        if (!clientTunnelOnError(this, context, request, parser_->method(), ERR_INVALID_REQ)) {
            setReplyError(context, request, parser_->method(), ERR_INVALID_REQ, Http::scBadRequest, requestErrorBytes);
            clientProcessRequestFinished(this, request);
        }
        return false;
    }

    // when absolute-URI is provided Host header should be ignored. However
    // some code still uses Host directly so normalize it using the previously
    // sanitized URL authority value.
    // For now preserve the case where Host is completely absent. That matters.
    if (const auto x = request->header.delById(Http::HOST)) {
        debugs(33, 5, "normalize " << x << " Host header using " << request->url.authority());
        SBuf tmp(request->url.authority());
        request->header.putStr(Http::HOST, tmp.c_str());
    }

    http->initRequest(request.getRaw());

    return true;
}

void
Http::One::Server::setReplyError(Http::StreamPointer &context, HttpRequest::Pointer &request, const HttpRequestMethod& method, err_type requestError, Http::StatusCode errStatusCode, const char *requestErrorBytes)
{
    quitAfterError(request.getRaw());
    if (!context->connRegistered()) {
        debugs(33, 2, "Client stream deregister it self, nothing to do");
        clientConnection->close();
        return;
    }
    clientStreamNode *node = context->getClientReplyContext();
    clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
    assert (repContext);

    repContext->setReplyToError(requestError, errStatusCode, method, context->http->uri, clientConnection->remote, nullptr, requestErrorBytes, nullptr);

    assert(context->http->out.offset == 0);
    context->pullData();
}

void
Http::One::Server::proceedAfterBodyContinuation(Http::StreamPointer context)
{
    debugs(33, 5, "Body Continuation written");
    clientProcessRequest(this, parser_, context.getRaw());
}

void
Http::One::Server::processParsedRequest(Http::StreamPointer &context)
{
    if (!buildHttpRequest(context))
        return;

    ClientHttpRequest *http = context->http;
    HttpRequest::Pointer request = http->request;

    if (request->header.has(Http::HdrType::EXPECT)) {
        const String expect = request->header.getList(Http::HdrType::EXPECT);
        const bool supportedExpect = (expect.caseCmp("100-continue") == 0);
        if (!supportedExpect) {
            clientStreamNode *node = context->getClientReplyContext();
            quitAfterError(request.getRaw());
            // setReplyToError() requires log_uri
            assert(http->log_uri);
            clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
            assert (repContext);
            repContext->setReplyToError(ERR_INVALID_REQ, Http::scExpectationFailed, request->method, http->uri,
                                        clientConnection->remote, request.getRaw(), NULL, NULL);
            assert(context->http->out.offset == 0);
            context->pullData();
            clientProcessRequestFinished(this, request);
            return;
        }

        if (Config.accessList.forceRequestBodyContinuation) {
            ACLFilledChecklist bodyContinuationCheck(Config.accessList.forceRequestBodyContinuation, request.getRaw(), NULL);
            bodyContinuationCheck.al = http->al;
            bodyContinuationCheck.syncAle(request.getRaw(), http->log_uri);
            if (bodyContinuationCheck.fastCheck().allowed()) {
                debugs(33, 5, "Body Continuation forced");
                request->forcedBodyContinuation = true;
                //sendControlMsg
                HttpReply::Pointer rep = new HttpReply;
                rep->sline.set(Http::ProtocolVersion(), Http::scContinue);

                typedef UnaryMemFunT<Http1::Server, Http::StreamPointer> CbDialer;
                const AsyncCall::Pointer cb = asyncCall(11, 3,  "Http1::Server::proceedAfterBodyContinuation", CbDialer(this, &Http1::Server::proceedAfterBodyContinuation, Http::StreamPointer(context)));
                sendControlMsg(HttpControlMsg(rep, cb));
                return;
            }
        }
    }
    clientProcessRequest(this, parser_, context.getRaw());
}

void
Http::One::Server::noteBodyConsumerAborted(BodyPipe::Pointer ptr)
{
    ConnStateData::noteBodyConsumerAborted(ptr);
    stopReceiving("virgin request body consumer aborted"); // closes ASAP
}

void
Http::One::Server::handleReply(HttpReply *rep, StoreIOBuffer receivedData)
{
    // the caller guarantees that we are dealing with the current context only
    Http::StreamPointer context = pipeline.front();
    Must(context != nullptr);
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
        context->writeComplete(0);
        return;
    }

    if (!context->startOfOutput()) {
        context->sendBody(receivedData);
        return;
    }

    assert(rep);
    HTTPMSGUNLOCK(http->al->reply);
    http->al->reply = rep;
    HTTPMSGLOCK(http->al->reply);
    context->sendStartOfMessage(rep, receivedData);
}

bool
Http::One::Server::writeControlMsgAndCall(HttpReply *rep, AsyncCall::Pointer &call)
{
    Http::StreamPointer context = pipeline.front();
    Must(context != nullptr);

    // Ignore this late control message if we have started sending a
    // reply to the user already (e.g., after an error).
    if (context->reply) {
        debugs(11, 2, "drop 1xx made late by " << context->reply);
        return false;
    }

    const ClientHttpRequest *http = context->http;

    // apply selected clientReplyContext::buildReplyHeader() mods
    // it is not clear what headers are required for control messages
    rep->header.removeHopByHopEntries();
    rep->header.putStr(Http::HdrType::CONNECTION, "keep-alive");
    httpHdrMangleList(&rep->header, http->request, http->al, ROR_REPLY);

    MemBuf *mb = rep->pack();

    debugs(11, 2, "HTTP Client " << clientConnection);
    debugs(11, 2, "HTTP Client CONTROL MSG:\n---------\n" << mb->buf << "\n----------");

    Comm::Write(clientConnection, mb, call);

    delete mb;
    return true;
}

ConnStateData *
Http::NewServer(MasterXactionPointer &xact)
{
    return new Http1::Server(xact, false);
}

ConnStateData *
Https::NewServer(MasterXactionPointer &xact)
{
    return new Http1::Server(xact, true);
}

