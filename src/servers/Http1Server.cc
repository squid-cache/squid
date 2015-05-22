/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
#include "HttpHeaderTools.h"
#include "profiler/Profiler.h"
#include "servers/Http1Server.h"
#include "SquidConfig.h"

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

ClientSocketContext *
Http::One::Server::parseOneRequest()
{
    PROF_start(HttpServer_parseOneRequest);

    // parser is incremental. Generate new parser state if we,
    // a) dont have one already
    // b) have completed the previous request parsing already
    if (!parser_ || !parser_->needsMoreData())
        parser_ = new Http1::RequestParser();

    /* Process request */
    ClientSocketContext *context = parseHttpRequest(this, parser_);

    PROF_stop(HttpServer_parseOneRequest);
    return context;
}

void clientProcessRequestFinished(ConnStateData *conn, const HttpRequest::Pointer &request);
bool clientTunnelOnError(ConnStateData *conn, ClientSocketContext *context, HttpRequest *request, const HttpRequestMethod& method, err_type requestError, Http::StatusCode errStatusCode, const char *requestErrorBytes);

bool
Http::One::Server::buildHttpRequest(ClientSocketContext *context)
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
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri, true);
        const char * requestErrorBytes = in.buf.c_str();
        if (!clientTunnelOnError(this, context, request.getRaw(), parser_->method(), errPage, parser_->parseStatusCode, requestErrorBytes)) {
            // HttpRequest object not build yet, there is no reason to call
            // clientProcessRequestFinished method
        }

        return false;
    }

    if ((request = HttpRequest::CreateFromUrlAndMethod(http->uri, parser_->method())) == NULL) {
        debugs(33, 5, "Invalid URL: " << http->uri);
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri, true);

        const char * requestErrorBytes = in.buf.c_str();
        if (!clientTunnelOnError(this, context, request.getRaw(), parser_->method(), ERR_INVALID_URL, Http::scBadRequest, requestErrorBytes)) {
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
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri,  true);

        const char * requestErrorBytes = NULL; //HttpParserHdrBuf(parser_);
        if (!clientTunnelOnError(this, context, request.getRaw(), parser_->method(), ERR_UNSUP_HTTPVERSION, Http::scHttpVersionNotSupported, requestErrorBytes)) {
            clientProcessRequestFinished(this, request);
        }
        return false;
    }

    /* compile headers */
    if (parser_->messageProtocol().major >= 1 && !request->parseHeader(*parser_.getRaw())) {
        debugs(33, 5, "Failed to parse request headers:\n" << parser_->mimeHeader());
        // setLogUri should called before repContext->setReplyToError
        setLogUri(http, http->uri, true);
        const char * requestErrorBytes = NULL; //HttpParserHdrBuf(parser_);
        if (!clientTunnelOnError(this, context, request.getRaw(), parser_->method(), ERR_INVALID_REQ, Http::scBadRequest, requestErrorBytes)) {
            clientProcessRequestFinished(this, request);
        }
        return false;
    }

    http->request = request.getRaw();
    HTTPMSGLOCK(http->request);

    return true;
}

void
Http::One::Server::proceedAfterBodyContinuation(ClientSocketContext::Pointer context)
{
    debugs(33, 5, "Body Continuation written");
    clientProcessRequest(this, parser_, context.getRaw());
}

void
Http::One::Server::processParsedRequest(ClientSocketContext *context)
{
    if (!buildHttpRequest(context))
        return;

    ClientHttpRequest *http = context->http;
    HttpRequest::Pointer request = http->request;

    if (request->header.has(HDR_EXPECT)) {
        const String expect = request->header.getList(HDR_EXPECT);
        const bool supportedExpect = (expect.caseCmp("100-continue") == 0);
        if (!supportedExpect) {
            clientStreamNode *node = context->getClientReplyContext();
            quitAfterError(request.getRaw());
            // setLogUri should called before repContext->setReplyToError
            setLogUri(http, urlCanonicalClean(request.getRaw()));
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
            if (bodyContinuationCheck.fastCheck() == ACCESS_ALLOWED) {
                debugs(33, 5, "Body Continuation forced");
                request->forcedBodyContinuation = true;
                //sendControlMsg
                HttpReply::Pointer rep = new HttpReply;
                rep->sline.set(Http::ProtocolVersion(), Http::scContinue);

                typedef UnaryMemFunT<Http1::Server, ClientSocketContext::Pointer> CbDialer;
                const AsyncCall::Pointer cb = asyncCall(11, 3,  "Http1::Server::proceedAfterBodyContinuation", CbDialer(this, &Http1::Server::proceedAfterBodyContinuation, ClientSocketContext::Pointer(context)));
                sendControlMsg(HttpControlMsg(rep, cb));
                return;
            }
        }
    }
    clientProcessRequest(this, parser_, context);
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
    ClientSocketContext::Pointer context = getCurrentContext();
    Must(context != NULL);
    const ClientHttpRequest *http = context->http;
    Must(http != NULL);

    // After sending Transfer-Encoding: chunked (at least), always send
    // the last-chunk if there was no error, ignoring responseFinishedOrFailed.
    const bool mustSendLastChunk = http->request->flags.chunkedReply &&
                                   !http->request->flags.streamError &&
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

void
Http::One::Server::writeControlMsgAndCall(ClientSocketContext *context, HttpReply *rep, AsyncCall::Pointer &call)
{
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

