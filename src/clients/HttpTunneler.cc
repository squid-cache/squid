/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "CachePeer.h"
#include "clients/HttpTunneler.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "http.h"
#include "http/one/ResponseParser.h"
#include "http/StateFlags.h"
#include "HttpRequest.h"
#include "neighbors.h"
#include "pconn.h"
#include "SquidConfig.h"
#include "StatCounters.h"

CBDATA_NAMESPACED_CLASS_INIT(Http, Tunneler);

Http::Tunneler::Tunneler(const Comm::ConnectionPointer &conn, const HttpRequest::Pointer &req, const AsyncCallback<Answer> &aCallback, const time_t timeout, const AccessLogEntryPointer &alp):
    AsyncJob("Http::Tunneler"),
    noteFwdPconnUse(false),
    connection(conn),
    request(req),
    callback(aCallback),
    lifetimeLimit(timeout),
    al(alp),
    startTime(squid_curtime),
    requestWritten(false),
    tunnelEstablished(false)
{
    debugs(83, 5, "Http::Tunneler constructed, this=" << (void*)this);
    assert(request);
    assert(connection);
    url = request->url.authority(true);
    watchForClosures();
}

Http::Tunneler::~Tunneler()
{
    debugs(83, 5, "Http::Tunneler destructed, this=" << (void*)this);
}

bool
Http::Tunneler::doneAll() const
{
    return !callback || (requestWritten && tunnelEstablished);
}

void
Http::Tunneler::start()
{
    AsyncJob::start();

    Must(al);
    Must(url.length());
    Must(lifetimeLimit >= 0);

    // we own this Comm::Connection object and its fd exclusively, but must bail
    // if others started closing the socket while we were waiting to start()
    assert(Comm::IsConnOpen(connection));
    if (fd_table[connection->fd].closing()) {
        bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw(), al));
        return;
    }

    const auto peer = connection->getPeer();
    // bail if our peer was reconfigured away
    if (!peer) {
        bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scInternalServerError, request.getRaw(), al));
        return;
    }
    request->prepForPeering(*peer);

    writeRequest();
    startReadingResponse();
}

void
Http::Tunneler::handleConnectionClosure(const CommCloseCbParams &)
{
    closer = nullptr;
    if (connection) {
        countFailingConnection(nullptr);
        connection->noteClosure();
        connection = nullptr;
    }
    bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw(), al));
}

/// make sure we quit if/when the connection is gone
void
Http::Tunneler::watchForClosures()
{
    Must(Comm::IsConnOpen(connection));
    Must(!fd_table[connection->fd].closing());

    debugs(83, 5, connection);

    Must(!closer);
    typedef CommCbMemFunT<Http::Tunneler, CommCloseCbParams> Dialer;
    closer = JobCallback(9, 5, Dialer, this, Http::Tunneler::handleConnectionClosure);
    comm_add_close_handler(connection->fd, closer);
}

/// The connection read timeout callback handler.
void
Http::Tunneler::handleTimeout(const CommTimeoutCbParams &)
{
    bailWith(new ErrorState(ERR_CONNECT_FAIL, Http::scGatewayTimeout, request.getRaw(), al));
}

void
Http::Tunneler::startReadingResponse()
{
    debugs(83, 5, connection << status());

    readBuf.reserveCapacity(SQUID_TCP_SO_RCVBUF);
    readMore();
}

void
Http::Tunneler::writeRequest()
{
    debugs(83, 5, connection);

    Http::StateFlags flags;
    flags.peering = true;
    // flags.tunneling = false; // the CONNECT request itself is not tunneled
    // flags.toOrigin = false; // the next HTTP hop is a non-originserver peer

    MemBuf mb;

    try {
        request->masterXaction->generatingConnect = true;

        mb.init();
        mb.appendf("CONNECT %s HTTP/1.1\r\n", url.c_str());
        HttpHeader hdr_out(hoRequest);
        HttpStateData::httpBuildRequestHeader(request.getRaw(),
                                              nullptr, // StoreEntry
                                              al,
                                              &hdr_out,
                                              flags);
        hdr_out.packInto(&mb);
        hdr_out.clean();
        mb.append("\r\n", 2);

        request->masterXaction->generatingConnect = false;
    } catch (...) {
        // TODO: Add scope_guard; do not wait until it is in the C++ standard.
        request->masterXaction->generatingConnect = false;
        throw;
    }

    debugs(11, 2, "Tunnel Server REQUEST: " << connection <<
           ":\n----------\n" << mb.buf << "\n----------");
    fd_note(connection->fd, "Tunnel Server CONNECT");

    typedef CommCbMemFunT<Http::Tunneler, CommIoCbParams> Dialer;
    writer = JobCallback(5, 5, Dialer, this, Http::Tunneler::handleWrittenRequest);
    Comm::Write(connection, &mb, writer);
}

/// Called when we are done writing a CONNECT request header to a peer.
void
Http::Tunneler::handleWrittenRequest(const CommIoCbParams &io)
{
    Must(writer);
    writer = nullptr;

    if (io.flag == Comm::ERR_CLOSING)
        return;

    request->hier.notePeerWrite();

    if (io.flag != Comm::OK) {
        const auto error = new ErrorState(ERR_WRITE_ERROR, Http::scBadGateway, request.getRaw(), al);
        error->xerrno = io.xerrno;
        bailWith(error);
        return;
    }

    statCounter.server.all.kbytes_out += io.size;
    statCounter.server.other.kbytes_out += io.size;
    requestWritten = true;
    debugs(83, 5, status());
}

/// Called when we read [a part of] CONNECT response from the peer
void
Http::Tunneler::handleReadyRead(const CommIoCbParams &io)
{
    Must(reader);
    reader = nullptr;

    if (io.flag == Comm::ERR_CLOSING)
        return;

    CommIoCbParams rd(this);
    rd.conn = io.conn;
#if USE_DELAY_POOLS
    rd.size = delayId.bytesWanted(1, readBuf.spaceSize());
#else
    rd.size = readBuf.spaceSize();
#endif
    // XXX: defer read if rd.size <= 0

    switch (Comm::ReadNow(rd, readBuf)) {
    case Comm::INPROGRESS:
        readMore();
        return;

    case Comm::OK: {
#if USE_DELAY_POOLS
        delayId.bytesIn(rd.size);
#endif
        statCounter.server.all.kbytes_in += rd.size;
        statCounter.server.other.kbytes_in += rd.size; // TODO: other or http?
        request->hier.notePeerRead();
        handleResponse(false);
        return;
    }

    case Comm::ENDFILE: {
        // TODO: Should we (and everybody else) call request->hier.notePeerRead() on zero reads?
        handleResponse(true);
        return;
    }

    // case Comm::COMM_ERROR:
    default: // no other flags should ever occur
    {
        const auto error = new ErrorState(ERR_READ_ERROR, Http::scBadGateway, request.getRaw(), al);
        error->xerrno = rd.xerrno;
        bailWith(error);
        return;
    }
    }

    assert(false); // not reached
}

void
Http::Tunneler::readMore()
{
    Must(Comm::IsConnOpen(connection));
    Must(!fd_table[connection->fd].closing());
    Must(!reader);

    typedef CommCbMemFunT<Http::Tunneler, CommIoCbParams> Dialer;
    reader = JobCallback(93, 3, Dialer, this, Http::Tunneler::handleReadyRead);
    Comm::Read(connection, reader);

    AsyncCall::Pointer nil;
    typedef CommCbMemFunT<Http::Tunneler, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall = JobCallback(93, 5,
                                     TimeoutDialer, this, Http::Tunneler::handleTimeout);
    const auto timeout = Comm::MortalReadTimeout(startTime, lifetimeLimit);
    commSetConnTimeout(connection, timeout, timeoutCall);
}

/// Parses [possibly incomplete] CONNECT response and reacts to it.
void
Http::Tunneler::handleResponse(const bool eof)
{
    // mimic the basic parts of HttpStateData::processReplyHeader()
    if (hp == nullptr)
        hp = new Http1::ResponseParser;

    auto parsedOk = hp->parse(readBuf); // may be refined below
    readBuf = hp->remaining();
    if (hp->needsMoreData()) {
        if (!eof) {
            if (readBuf.length() >= SQUID_TCP_SO_RCVBUF) {
                bailOnResponseError("huge CONNECT response from peer", nullptr);
                return;
            }
            readMore();
            return;
        }

        //eof, handle truncated response
        readBuf.append("\r\n\r\n", 4);
        parsedOk = hp->parse(readBuf);
        readBuf.clear();
    }

    if (!parsedOk) {
        bailOnResponseError("malformed CONNECT response from peer", nullptr);
        return;
    }

    HttpReply::Pointer rep = new HttpReply;
    rep->sources |= Http::Message::srcHttp;
    rep->sline.set(hp->messageProtocol(), hp->messageStatus());
    if (!rep->parseHeader(*hp) && rep->sline.status() == Http::scOkay) {
        bailOnResponseError("malformed CONNECT response from peer", nullptr);
        return;
    }

    // CONNECT response was successfully parsed
    auto &futureAnswer = callback.answer();
    futureAnswer.peerResponseStatus = rep->sline.status();
    request->hier.peer_reply_status = rep->sline.status();

    debugs(11, 2, "Tunnel Server " << connection);
    debugs(11, 2, "Tunnel Server RESPONSE:\n---------\n" <<
           Raw(nullptr, readBuf.rawContent(), rep->hdr_sz).minLevel(2).gap(false) <<
           "----------");

    // bail if we did not get an HTTP 200 (Connection Established) response
    if (rep->sline.status() != Http::scOkay) {
        // TODO: To reuse the connection, extract the whole error response.
        bailOnResponseError("unsupported CONNECT response status code", rep.getRaw());
        return;
    }

    // preserve any bytes sent by the server after the CONNECT response
    futureAnswer.leftovers = readBuf;

    tunnelEstablished = true;
    debugs(83, 5, status());
}

void
Http::Tunneler::bailOnResponseError(const char *error, HttpReply *errorReply)
{
    debugs(83, 3, error << status());

    ErrorState *err;
    if (errorReply) {
        err = new ErrorState(request.getRaw(), errorReply);
    } else {
        // with no reply suitable for relaying, answer with 502 (Bad Gateway)
        err = new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request.getRaw(), al);
    }
    bailWith(err);
}

void
Http::Tunneler::bailWith(ErrorState *error)
{
    Must(error);
    callback.answer().squidError = error;

    if (const auto failingConnection = connection) {
        // TODO: Reuse to-peer connections after a CONNECT error response.
        countFailingConnection(error);
        disconnect();
        failingConnection->close();
    }

    callBack();
}

void
Http::Tunneler::sendSuccess()
{
    assert(callback.answer().positive());
    assert(Comm::IsConnOpen(connection));
    callback.answer().conn = connection;
    disconnect();
    callBack();
}

void
Http::Tunneler::countFailingConnection(const ErrorState * const error)
{
    assert(connection);
    NoteOutgoingConnectionFailure(connection->getPeer(), error ? error->httpStatus : Http::scNone);
    if (noteFwdPconnUse && connection->isOpen())
        fwdPconnPool->noteUses(fd_table[connection->fd].pconn.uses);
}

void
Http::Tunneler::disconnect()
{
    const auto stillOpen = Comm::IsConnOpen(connection);

    if (closer) {
        if (stillOpen)
            comm_remove_close_handler(connection->fd, closer);
        closer = nullptr;
    }

    if (reader) {
        if (stillOpen)
            Comm::ReadCancel(connection->fd, reader);
        reader = nullptr;
    }

    if (stillOpen)
        commUnsetConnTimeout(connection);

    connection = nullptr; // may still be open
}

void
Http::Tunneler::callBack()
{
    debugs(83, 5, callback.answer().conn << status());
    assert(!connection); // returned inside callback.answer() or gone
    ScheduleCallHere(callback.release());
}

void
Http::Tunneler::swanSong()
{
    AsyncJob::swanSong();

    if (callback) {
        if (requestWritten && tunnelEstablished && Comm::IsConnOpen(connection)) {
            sendSuccess();
        } else {
            // job-ending emergencies like handleStopRequest() or callException()
            bailWith(new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al));
        }
        assert(!callback);
    }
}

const char *
Http::Tunneler::status() const
{
    static MemBuf buf;
    buf.reset();

    // TODO: redesign AsyncJob::status() API to avoid
    // id and stop reason reporting duplication.
    buf.append(" [state:", 8);
    if (requestWritten) buf.append("w", 1); // request sent
    if (tunnelEstablished) buf.append("t", 1); // tunnel established
    if (!callback) buf.append("x", 1); // caller informed
    if (stopReason != nullptr) {
        buf.append(" stopped, reason:", 16);
        buf.appendf("%s",stopReason);
    }
    if (connection != nullptr)
        buf.appendf(" FD %d", connection->fd);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

