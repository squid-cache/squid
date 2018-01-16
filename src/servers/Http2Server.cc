/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 11    Hypertext Transfer Protocol (HTTP/2) */
/* DEBUG: section 33    Transfer protocol server for HTTP/2 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "http/Stream.h"
#include "http/two/FrameParser.h"
#include "http/two/FrameType.h"
#include "http/two/Settings.h"
#include "http/two/StreamContext.h"
#include "MasterXaction.h"
#include "MemBuf.h"
#include "servers/Http2Server.h"

#include <algorithm>

CBDATA_NAMESPACED_CLASS_INIT(Http2, Server);

Http::Two::Server::Server(const MasterXaction::Pointer &xact) :
        AsyncJob("Http2::Server"),
        ::Server(xact),
        seenFirstSettings(false),
        clientSettings(Http2::StdDefaultSettings()),
        ourSettings(Http2::StdDefaultSettings()),
        lastUsedStreamId(0)
{}

void
Http::Two::Server::start()
{
    hp_ = new Http2::FrameParser;
    readSomeData();

    // TODO: emit SETTINGS containing Http2::SquidDefaultSettings()

    // XXX: temporary 9 bytes SETTINGS frame header with no payload
    static SBuf initialSettings("\0\0\0\4\0\0\0\0\0", 9);
    controlWriteQueue.push_back(initialSettings);
    // queue, but do not kick of writes until we receive the client SETTINGS
    // ACK-ing the client SETTINGS frame will deliver this one as well.
}

void
Http::Two::Server::swanSong()
{
    ::Server::swanSong(); // closes the connection, etc.
}

void
Http::Two::Server::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    // XXX: get the stream owning this BodyPipe and
    // schedule a WINDOW_UPDATE for the newly opened space
}

void
Http::Two::Server::noteBodyConsumerAborted(BodyPipe::Pointer)
{
    // XXX: get the stream owning this BodyPipe and
    // send a RST_STREAM
}

void
Http::Two::Server::notifyAllContexts(const int xerrno)
{
    // TODO: handle the connection TCP I/O error
}

bool
Http::Two::Server::connFinishedWithConn(int)
{
    // are we done with the client connection?

    // return false if there are streams still sending
    if (activeStreams.empty())
        return true;

    for (auto i = activeStreams.cbegin(); i != activeStreams.cend(); ++i) {
        switch ((*i)->http2Stream->state)
        {
        case Http2::IDLE:
        case Http2::RESERVED_LOCAL:
        case Http2::RESERVED_REMOTE:
        case Http2::CLOSED:
            // streams to ignore.
        case Http2::CLOSED_LOCAL:
            // we were still waiting on client, but they will not finish now.
            break;

        case Http2::OPEN:
        case Http2::CLOSED_REMOTE:
            return false; // stream active for sending
            break;
        }
    }

    // if there are no active streams, let the connection be closed.
    return true;
}

bool
Http::Two::Server::connectionError(const Http2::ErrorCode /*errType*/, const char *reasonPhrase)
{
    // TODO send GOAWAY frame with type reasonCode
    debugs(11, 2, "HTTP/2 Aborting. " << reasonPhrase << " on FD " <<
           clientConnection->fd << " stream=" << hp_->frameStreamId());
    clientConnection->close();
    return false;
}

// return true if caller should continue operating
bool
Http::Two::Server::handleReadData()
{
    // HTTP/2 handles data as whole frames.
    do {
        const bool parsedOneFrame = hp_->parse(inBuf);

        // sync the buffers after parsing.
        inBuf = hp_->remaining();

        if (!parsedOneFrame) {
            if (hp_->needsMoreData()) {
                debugs(11, 5, "Incomplete frame, waiting for end of frame on " << clientConnection);
                readSomeData();
                return true;
            }

            // else parse failure => connection error

            // TODO: emit GOAWAY and finish sending active streams before close
            return connectionError(Http2::PROTOCOL_ERROR, "Frame parse error");
        }

    } while (handleFrame());

    // if we get to here the last frame triggered connection closure.
    return false;
}

/// update our stored details of client SETTINGS
/// \return false if an error occurred
bool
Http::Two::Server::applySettings(Http2::SettingsMap &toBeSet, const SBuf &payload, bool doAck)
{
    debugs(11, 2, "HTTP/2: SETTINGS frame on " << clientConnection);

    /* NOTE: RFC 7540 section 6.5.3
     * SETTINGS values MUST be applied 'atomically' in the order presented
     * with no other HTTP/2 processing on this connection occurring between.
     */

    /* RFC 7540 section 6.5
     * A SETTINGS frame with a length other than a multiple of 6 octets MUST
     * be treated as a connection error of type FRAME_SIZE_ERROR.
     */
    if ((payload.length() % 6) != 0) {
        // abort connection, not HTTP/2 compliant. SETTINGS payload is a list of 6-byte kv-pair.
        return connectionError(Http2::FRAME_SIZE_ERROR, "SETTINGS frame with impossible payload size");
    }

    // parse SETTINGS payload (series of 16-bit,32-bit kv-pairs)
    const struct SettingParameter *params = reinterpret_cast<const SettingParameter*>(payload.rawContent());
    const size_t numParams = payload.length() / sizeof(struct SettingParameter);

    for (size_t i = 0; i < numParams; ++i) {
        // only do the accessor bit-shifting once
        const uint16_t t = params[i].type();
        const uint32_t v = params[i].value();
        switch (t) {
        case Http2::SETTINGS_HEADER_TABLE_SIZE:
            debugs(11, 2, " parameter type=HEADER_TABLE_SIZE, value=" << v);
            // XXX: HPACK will need to act on this ...
            break;

        case Http2::SETTINGS_ENABLE_PUSH:
            debugs(11, 2, " parameter type=ENABLE_PUSH, value=" << v);
            /* RFC 7540 section 6.5.2:
             * Any value other than 0 or 1 MUST be treated as a connection error of type PROTOCOL_ERROR.
             */
            if (v >= 2)
                return connectionError(Http2::PROTOCOL_ERROR, "Invalid value for ENABLE_PUSH");
            break;

        case Http2::SETTINGS_MAX_CONCURRENT_STREAMS:
            debugs(11, 2, " parameter type=MAX_CONCURRENT_STREAMS, value=" << v);
            break;

        case Http2::SETTINGS_INITIAL_WINDOW_SIZE:
            debugs(11, 2, " parameter type=INITIAL_WINDOW_SIZE, value=" << v);
            /* RFC 7540 section 6.5.2:
             * Values above 2^31-1 MUST be treated as a connection error of type FLOW_CONTROL_ERROR.
             */
            if (v > (1<<31)-1)
                return connectionError(Http2::FLOW_CONTROL_ERROR, "Invalid INITIAL_WINDOW_SIZE");
            break;

        case Http2::SETTINGS_MAX_FRAME_SIZE:
            debugs(11, 2, " parameter type=MAX_FRAME_SIZE, value=" << v);
            /* RFC 7540 section 6.5.2:
             *  The initial value is 2^14 (16,384) octets.  The value advertised
             *  by an endpoint MUST be between this initial value and the maximum
             *  allowed frame size (2^24-1 or 16,777,215 octets), inclusive.
             *  Values outside this range MUST be treated as a connection error
             *  of type PROTOCOL_ERROR.
             */
            if (v < MaxFramePayloadSz || Http2::MaxFrameExtendedSz < v)
                return connectionError(Http2::PROTOCOL_ERROR, "Invalid MAX_FRAME_SIZE");
            break;

        case Http2::SETTINGS_MAX_HEADER_LIST_SIZE:
            debugs(11, 2, " parameter type=MAX_HEADER_LIST_SIZE, value=" << v);
            // XXX: HPACK might need to act on this ? ...
            break;

        default:
            /* RFC 7540 section 6.5.2:
             *  An endpoint that receives a SETTINGS frame with any unknown or
             *  unsupported identifier MUST ignore that setting.
             */
            debugs(11, 2, " parameter type=" << t << " (unknown), value=" << v);
            continue;
        }

        // action the setting change
        toBeSet[t] = v;
    }

    // ACK the SETTINGS if required
    if (doAck) {
        // 9 bytes SETTINGS frame header (with ACK flag, no payload)
        static SBuf settingsAck("\0\0\0\4\1\0\0\0\0", 9);
        controlWriteQueue.push_back(settingsAck);
        writeSomeData();
    }

    return true;
}

/// function class used to search a list of active streams for a given ID
struct StreamIdLookup
{
    explicit StreamIdLookup(uint32_t anId) : findId(anId) {}
    bool operator() (const MasterXaction::Pointer &c) const {
        return (c->http2Stream != NULL && c->http2Stream->id == findId);
    }
private:
    uint32_t findId;
};

/// \returns true if caller should continue operating
bool
Http::Two::Server::processHeadersFrame()
{
    /* RFC 7540 section 6.2:
     *  The HEADERS frame (type=0x1) is used to open a stream (Section 5.1),
     *  and additionally carries a header block fragment.  HEADERS frames can
     *  be sent on a stream in the "idle", "reserved (local)", "open", or
     *  "half-closed (remote)" state.
     */
    const auto streamId = hp_->frameStreamId();

    if (streamId == 0x0) {
        /* If a HEADERS frame is received whose stream identifier field is 0x0,
         * the recipient MUST respond with a connection error of type PROTOCOL_ERROR.
         */
        return connectionError(Http2::PROTOCOL_ERROR, "HEADERS for stream ID 0x0");
    }

    Http2::StreamContextPointer s;

    // streams > lastUsedStreamId are IDLE.
    if (streamId <= lastUsedStreamId) {
        // if the stream ID is not higher than any previously seen, it must be an active
        // stream already. If not PROTOCOL_ERROR.
        auto x = std::find_if(activeStreams.cbegin(), activeStreams.cend(), StreamIdLookup(streamId));
        // not found means stream is CLOSED.
        if (x == activeStreams.cend())
            return connectionError(Http2::PROTOCOL_ERROR, "HEADERS for CLOSED stream");

        s = (*x)->http2Stream;
        assert(s != nullptr);

        // To get here it is not IDLE and not CLOSED.
        // RESERVED_LOCAL is valid but means *we* are the one emitting HEADERS.
        // So only OPEN and RESERVED_REMOTE are okay to be received here.
        if (s->state != Http2::OPEN && s->state != Http2::RESERVED_REMOTE)
            return connectionError(Http2::PROTOCOL_ERROR, "HEADERS for existing stream");
    }

    lastUsedStreamId = max(lastUsedStreamId, streamId);

    if (!s) {
        MasterXaction::Pointer x = new MasterXaction(XactionInitiator::initClient);
        x->tcpClient = clientConnection;
        x->squidPort = port;
        x->http2Stream = s = new Http2::StreamContext();
        activeStreams.push_back(x);
    }
    s->update(hp_);

    // XXX: skip since parser decompressed payload into mime?
    // or process the pseudo-headers into request-line URL ?

    return true;
}

// return true if caller should continue operating
bool
Http::Two::Server::handleFrame()
{
    /*
     * first frame MUST be a SETTINGS frame
     */
    if (!seenFirstSettings && hp_->frameType() != Http2::SETTINGS)
        return connectionError(Http2::PROTOCOL_ERROR, "Frame #1 was not client SETTINGS");

    switch (hp_->frameType()) {
    case Http2::DATA:
        lastUsedStreamId = max(lastUsedStreamId, hp_->frameStreamId());
        debugs(11, 2, "HTTP/2 DATA received on " << clientConnection);
        // TODO check if stream is active, notify its BodyPipe of the payload SBuf to handle
        break;

    case Http2::HEADERS:
        debugs(11, 2, "HTTP/2 HEADERS received on " << clientConnection);
        return processHeadersFrame();
        break;

    case Http2::PRIORITY: // ignore for now
        lastUsedStreamId = max(lastUsedStreamId, hp_->frameStreamId());
        /* RFC 7540 section 6.3
         * If a PRIORITY frame is received with a stream identifier of 0x0, the
         * recipient MUST respond with a connection error of type PROTOCOL_ERROR.
         */
        if (hp_->frameStreamId() == 0)
            return connectionError(Http2::PROTOCOL_ERROR, "PRIORITY frame for control stream");

        /* RFC 7540 section 6.3
         * A PRIORITY frame with a length other than 5 octets MUST be treated as
         * a stream error of type FRAME_SIZE_ERROR.
         */
        if (!hp_->framePayload().isEmpty())
            return connectionError(Http2::FRAME_SIZE_ERROR, "Oversize PRIORITY frame");

        debugs(11, 2, "HTTP/2 ignore PRIORITY received on " << clientConnection);
        break;

    case Http2::RST_STREAM:
        /* RFC 7540 section 6.4
         * If a RST_STREAM frame is received with a stream identifier of 0x0, the
         * recipient MUST treat this as a connection error of type PROTOCOL_ERROR.
         */
        if (hp_->frameStreamId() == 0)
            return connectionError(Http2::PROTOCOL_ERROR, "RST_STREAM received for control stream");

        /* RFC 7540 section 6.4
         * If a RST_STREAM frame identifying an idle stream is received, the
         * recipient MUST treat this as a connection error of type PROTOCOL_ERROR.
         */
        if (hp_->frameStreamId() > lastUsedStreamId)
            return connectionError(Http2::PROTOCOL_ERROR, "RST_STREAM received for idle stream");

        /* RFC 7540 section 6.4
         * A RST_STREAM frame with a length other than 4 octets MUST be treated
         * as a connection error of type FRAME_SIZE_ERROR.
         */
        // TODO h2-nf: allow RST_STREAM with no payload
        if (hp_->framePayload().length() != 4)
            return connectionError(Http2::FRAME_SIZE_ERROR, "RST_STREAM received for idle stream");

        debugs(11, 2, "HTTP/2 RST_STREAM received on " << clientConnection);
        if (hp_->frameStreamId() <= lastUsedStreamId) {
            auto x = std::find_if(activeStreams.begin(), activeStreams.end(), StreamIdLookup(hp_->frameStreamId()));
            if (x != activeStreams.end()) {
               (*x)->http2Stream->update(hp_);
               activeStreams.erase(x);
            }
        }
        break;

    case Http2::SETTINGS:
        seenFirstSettings = true;
        debugs(11, 2, "HTTP/2 client SETTINGS received on " << clientConnection);
        if (hp_->frameStreamId() != 0)
            return connectionError(Http2::PROTOCOL_ERROR, "SETTINGS frame outside control stream");

        if ((hp_->frameFlags() & Http2::FLAG_ACK)) {
           /* RFC 7540 section 6.5:
            *  Receipt of a SETTINGS frame with the ACK flag set and a length
            *  field value other than 0 MUST be treated as a connection error
            *  of type FRAME_SIZE_ERROR.
            */
            if (hp_->framePayload().length() != 0)
                return connectionError(Http2::FRAME_SIZE_ERROR, "RST_STREAM received for idle stream");
           // Ack to our previous SETTINGS
           // update ourSettings with the one pendingSettings record we tried to get actioned
           // XXX: HTTP/2 just assumes the client actually understood and implemented all of the changes ACK'ed.
           // TODO h2-nf: echo and verify SETTINGS payload with ACK.
           SBuf tmp = pendingSettings.front();
           pendingSettings.pop_front();
           return applySettings(ourSettings, tmp, false);
        } else {
            // new client SETTINGS
            return applySettings(clientSettings, hp_->framePayload(), true);
        }
        break;

    case Http2::PUSH_PROMISE:
        lastUsedStreamId = max(lastUsedStreamId, hp_->frameStreamId());
        // XXX: PUSH can actually come from clients, we just dont accept it (yet).
        //  it does actually make sense for some types of client to push data to a cache (reverse-proxy)
        return connectionError(Http2::PROTOCOL_ERROR, "client sent PUSH_PROMISE");
        break;

    case Http2::PING:
        debugs(11, 2, "HTTP/2 PING received on " << clientConnection);
        if (hp_->frameStreamId() != 0)
            return connectionError(Http2::PROTOCOL_ERROR, "PING frame outside control stream");

        if ((hp_->frameFlags() & Http2::FLAG_ACK))
            return true; // PING was ACK'd, its keep-alive purpose is done.

        // TODO send pong
        break;

    case Http2::GOAWAY:
        debugs(11, 2, "HTTP/2 GOAWAY received on " << clientConnection);
        // TODO
        break;

    case Http2::WINDOW_UPDATE:
        debugs(11, 2, "HTTP/2 WINDOW_UPDATE received on " << clientConnection);
        // TODO
        break;

    case Http2::CONTINUATION:
        lastUsedStreamId = max(lastUsedStreamId, hp_->frameStreamId());
        /* super-huge mime headers being sent by the client.
         * Apparently Google just absolutely *have* to be able to send a minimum of 4 GB (2^24 * 2)
         * worth of mime headers on a single HTTP request/reply.
         * NP: that is 4GB *after* compressing --> approx. 20GB of de-compressed headers with HPACK 80% compression ratio.
         *
         * Squid does not support more than 64KB (2^16) in de-compressed form, a single HEADERS
         * frame is capable of holding 2^24 in compressed form, so any use of CONTINUATION is
         * several orders of magnitude larger mime headers than we accept.
         *
         * TODO: one of the following:
         * A) generate 431 error, absorb the payload into HPACK state, and continue with other streams.
         *  - this is the end-to-end response, client may retry with smaller mime headers.
         *
         * B) generate RST_STREAM, absorb the payload into HPACK state, and continue with other streams.
         *  - this is the hop-by-hop response, client may re-route the massive request elsewhere.
         *
         * C) emit GOAWAY, drop this and future HPACK affecting frames, finish sending (only) active streams, close connection.
         *  - this is the "penalize badly behaving client" response,
         *    client may behave better after a re-connect, or re-route the massive request elsewhere.
         */
        debugs(11, 2, "HTTP/2 Aborting. client sent CONTINUATION on " << clientConnection);
        clientConnection->close(); // just abort for now.
        return false;
        break;

    case Http2::ALTSVC: // ignore, invalid from client?
        debugs(11, 2, "HTTP/2 ignore ALTSVC received on " << clientConnection);
        break;

    default:
        debugs(33, 5, "Unknown Frame type=" << hp_->frameType() << " on " << clientConnection);
        break;
    }

    return true;
}

/// attempt to write some data from the pending queues
void
Http::Two::Server::writeSomeData()
{
    // do nothing if we are already waiting on a write to complete
    if (writing())
        return;

    // TODO: aggregate all the data to be written into a single SBuf and batch-send.
    // XXX: Comm::Write cannot handle SBuf yet, so we aggregate into a MemBuf
    MemBuf outBuf;
    outBuf.init();

    // top priority: drain any control stream frames
    while (!controlWriteQueue.empty()) {
        SBuf s(controlWriteQueue.front());
        controlWriteQueue.pop_front();
        outBuf.append(s.rawContent(), s.length());
    }
    if (outBuf.hasContent()) {
        debugs(33, 5, "schedule " << outBuf.contentSize() << " bytes from control stream on " << clientConnection);
        typedef CommCbMemFunT<Server, CommIoCbParams> Dialer;
        writer = JobCallback(33, 5, Dialer, this, Server::clientWriteDone);
        Comm::Write(clientConnection, &outBuf, writer);
        return;
    }

    /* TODO: starting with oldest stream (head of availableStreams list)
     * and recursively checking streams it depends on:
     * - attempt to drain the non-flow-controlled frames for that stream
     * - attempt to drain the flow-controlled frames for that stream if there is available window
     */
}
