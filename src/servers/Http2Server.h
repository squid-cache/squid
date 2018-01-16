/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#ifndef SQUID_SERVERS_HTTP2SERVER_H
#define SQUID_SERVERS_HTTP2SERVER_H

#include "cbdata.h"
#include "http/two/ErrorCode.h"
#include "http/two/forward.h"
#include "http/two/Settings.h"
#include "MasterXaction.h"
#include "sbuf/List.h"
#include "servers/Server.h"

namespace Http {

namespace Two {

/**
 * Manages a connection from an HTTP/2 client.
 *
 * Splits frames between a set of active streams.
 * Packs Frames into the connection in multiplex.
 */
class Server : public ::Server
{
    CBDATA_CLASS(Server);

public:
    Server(const MasterXaction::Pointer &);
    virtual ~Server() {}

    /* ::Server API */
    virtual bool shouldCloseOnEof() const { return true; }
    virtual void notifyAllContexts(const int xerrno);
    virtual bool handleReadData();
    virtual void receivedFirstByte() {/* XXX: not implemented yet for HTTP/2 */}
    virtual bool connFinishedWithConn(int);
    virtual void afterClientRead() {/* not relevant to HTTP/2 */}
    virtual void checkLogging() {/* XXX: not implemented yet for HTTP/2 */}

    /* AsyncJob API */
    virtual void start();
    virtual bool doneAll() const {return ::Server::doneAll();}
    virtual void swanSong();

    /* BodyProducer API */
    virtual void noteMoreBodySpaceAvailable(BodyPipe::Pointer);
    virtual void noteBodyConsumerAborted(BodyPipe::Pointer);

private:
    bool connectionError(const Http2::ErrorCode errType, const char *reasonPhrase);
    bool handleFrame();
    bool applySettings(Http2::SettingsMap &toBeSet, const SBuf &payload, bool doAck);
    bool processHeadersFrame();

    /* ::Server API */
    virtual void writeSomeData();
    virtual void terminateAll(const Error &, const LogTagsErrors &) {/* XXX: not implemented yet for HTTP/2 */}

    /// parser to process HTTP/2.* protocol frames
    Http2::FrameParserPointer hp_;

    /// whether the initial SETTINGS exchange has taken place yet.
    bool seenFirstSettings;

    /// latest settings available from client
    /// to be used to restrict sending
    Http2::SettingsMap clientSettings;

    /// what we have told the client (acknowledged)
    /// to be used to validate received traffic
    Http2::SettingsMap ourSettings;

    /// what we have told the client (not yet acknowledged)
    SBufList pendingSettings;

    /// set of currently active streams/transactions ordered by stream-id
    std::list<MasterXaction::Pointer> activeStreams;

    /**
     * The last stream-id known to have been used on this connection.
     * Streams numbered above this are all in IDLE state.
     * Streams at or below this without an activeStreams entry are in CLOSED state.
     * When this reaches Http2::MaxStreamId the connection MUST stop initiating new streams.
     */
    uint32_t lastUsedStreamId;

    /// queue of pending frames to be written on the control stream
    SBufList controlWriteQueue;
};

} // namespace Two
} // namespace Http

#endif /* SQUID_SERVERS_HTTP2SERVER_H */
