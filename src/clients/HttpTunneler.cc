/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "clients/HttpTunneler.h"
#include "clients/HttpTunnelerAnswer.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "errorpage.h"
#include "fde.h"
#include "http.h"
#include "http/StateFlags.h"
#include "HttpRequest.h"
#include "StatCounters.h"
#include "SquidConfig.h"

CBDATA_NAMESPACED_CLASS_INIT(Http, Tunneler);

Http::Tunneler::Tunneler(AsyncCall::Pointer &aCallback):
    AsyncJob("Http::Tunneler"),
    callback(aCallback),
    lifetimeLimit(0),
    startTime(squid_curtime),
    requestWritten(false),
    tunnelEstablished(false)
{
    debugs(83, 5, "Http::Tunneler constructed, this=" << (void*)this);
    // detect callers supplying cb dialers that are not our CbDialer
    assert(callback);
    assert(dynamic_cast<CbDialer*>(callback->getDialer()));
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

/// convenience method to get to the answer fields
Http::TunnelerAnswer &
Http::Tunneler::answer()
{
    Must(callback);
    const auto dialer = dynamic_cast<CbDialer*>(callback->getDialer());
    Must(dialer);
    return dialer->answer();
}

void
Http::Tunneler::start()
{
    AsyncJob::start();

    Must(request);
    Must(connection);
    Must(al);
    Must(callback);
    Must(url.length());
    Must(lifetimeLimit >= 0);

    watchForClosures();
    writeRequest();
    startReadingResponse();
}

void
Http::Tunneler::handleConnectionClosure(const CommCloseCbParams &params)
{
    mustStop("server connection gone");
    callback = nullptr; // the caller must monitor closures
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

void
Http::Tunneler::handleException(const std::exception& e)
{
    debugs(83, 2, e.what() << status());
    connection->close();
    bailWith(new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al));
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

    HttpHeader hdr_out(hoRequest);
    Http::StateFlags flags;
    memset(&flags, '\0', sizeof(flags));
    flags.proxying = request->flags.proxying;
    MemBuf mb;
    mb.init();
    mb.appendf("CONNECT %s HTTP/1.1\r\n", url.c_str());
    HttpStateData::httpBuildRequestHeader(request.getRaw(),
                                          nullptr, // StoreEntry
                                          al,
                                          &hdr_out,
                                          flags);
    hdr_out.packInto(&mb);
    hdr_out.clean();
    mb.append("\r\n", 2);

    debugs(11, 2, "Tunnel Server REQUEST: " << connection <<
           ":\n----------\n" << mb.buf << "\n----------");

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
    rd.size = readBuf.spaceSize(); // XXX: from.bytesWanted(...)

    switch (Comm::ReadNow(rd, readBuf)) {
    case Comm::INPROGRESS:
        readMore();
        return;

    case Comm::OK: {
#if USE_DELAY_POOLS && XXX_IMPLEMENT
        delayId.bytesIn(rd.size);
#endif
        statCounter.server.all.kbytes_in += rd.size;
        statCounter.server.other.kbytes_in += rd.size; // TODO: other or http?
        request->hier.notePeerRead();
        len += rd.size;
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

    // TODO: Same as PeerConnector, but who removes this timeout after we send a
    // positive answer? Should not we clean after ourselves in swanSong()?
    AsyncCall::Pointer nil;
    Comm::SetClientObjectReadTimeout(connection, startTime, lifetimeLimit, nil);
}

/// Parses [possibly incomplete] CONNECT response and reacts to it.
void
Http::Tunneler::handleResponse(const bool eof)
{
    // mimic the basic parts of HttpStateData::processReplyHeader()
    // TODO: HttpStateData::processReplyHeader() tries harder on eof!
    // TODO: Do not parse headers. Use Http1::ResponseParser. See HttpStateData::processReplyHeader().
    HttpReply::Pointer rep = new HttpReply;
    Http::StatusCode parseErr = Http::scNone;
    const bool parsed = rep->parse(readBuf.c_str(), readBuf.length(), eof, &parseErr);
    if (!parsed) {
        if (parseErr > 0) { // unrecoverable parsing error
            bailOnResponseError("malformed CONNECT response from peer", nullptr);
            return;
        }

        // need more data
        assert(!eof);
        assert(!parseErr);

        if (readBuf.length() >= SQUID_TCP_SO_RCVBUF) {
            bailOnResponseError("huge CONNECT response from peer", nullptr);
            return;
        }

        readMore();
        return;
    }

    // CONNECT response was successfully parsed
    auto &futureAnswer = answer();
    futureAnswer.peerResponseStatus = rep->sline.status();
    request->hier.peer_reply_status = rep->sline.status();

    // XXX: Raw() prints an extra leading space. TODO: Add/use Raw::gap(false).
    debugs(11, 2, "HTTP Server " << connection);
    debugs(11, 2, "HTTP Server RESPONSE:\n---------\n" <<
           Raw(nullptr, readBuf.rawContent(), rep->hdr_sz).minLevel(2) <<
           "----------");

    // bail if we did not get an HTTP 200 (Connection Established) response
    if (rep->sline.status() != Http::scOkay) {
        // TODO: To reuse the connection, extract the whole error response.
        bailOnResponseError("unsupported CONNECT response status code", rep.getRaw());
        return;
    }

    // preserve any bytes sent by the server after the CONNECT response
    futureAnswer.leftovers = readBuf.substr(rep->hdr_sz);
    // delay pools were using this field to throttle CONNECT response
    len = futureAnswer.leftovers.length();

    tunnelEstablished = true;
    debugs(83, 5, status());
}

void
Http::Tunneler::bailOnResponseError(const char *error, HttpReply *errorReply)
{
    debugs(83, 3, error << status());

    ErrorState *err;
    if (errorReply) {
        err = new ErrorState(errorReply);
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
    answer().squidError = error;
    callBack();
}

void
Http::Tunneler::callBack()
{
    debugs(83, 5, connection << status());
    auto cb = callback;
    callback = nullptr;
    ScheduleCallHere(cb);
}

void
Http::Tunneler::swanSong()
{
    AsyncJob::swanSong();

    if (callback) {
        if (requestWritten && tunnelEstablished) {
            assert(answer().positive());
            callBack(); // success
        } else {
            // we should have bailed when we discovered the job-killing problem
            debugs(83, DBG_IMPORTANT, "BUG: Unexpected state while establishing a CONNECT tunnel " << connection << status());
            bailWith(new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw(), al));
        }
        assert(!callback);
    }

    if (closer) {
        comm_remove_close_handler(connection->fd, closer);
        closer = nullptr;
    }

    if (reader) {
        Comm::ReadCancel(connection->fd, reader);
        reader = nullptr;
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
    
    if (stopReason != NULL) {
        buf.append(" stopped, reason:", 16);
        buf.appendf("%s",stopReason);
    }
    if (connection != NULL)
        buf.appendf(" FD %d", connection->fd);
    buf.appendf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}
