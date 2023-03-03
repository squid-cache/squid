/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_STATEFLAGS_H
#define SQUID_SRC_HTTP_STATEFLAGS_H

namespace Http
{

class StateFlags
{
public:
    unsigned int front_end_https = 0; ///< send "Front-End-Https: On" header (off/on/auto=2)

    /// whether the Squid-sent request offers to keep the connection persistent
    bool keepalive = false;

    /// whether Squid should not keep the connection persistent despite offering
    /// to do so previously (and setting the keepalive flag)
    bool forceClose = false;

    bool only_if_cached = false;

    /// Whether we are processing an HTTP 1xx control message.
    bool handling1xx = false;

    /// Whether we received an HTTP 101 (Switching Protocols) control message.
    /// Implies true handling1xx, but the serverSwitchedProtocols state is
    /// permanent/final while handling of other control messages usually stops.
    bool serverSwitchedProtocols = false;

    bool headers_parsed = false;

    /// Whether the next TCP hop is a cache_peer, including originserver
    bool peering = false;

    /// Whether this request is being forwarded inside a CONNECT tunnel
    /// through a [non-originserver] cache_peer; implies peering and toOrigin
    bool tunneling = false;

    /// Whether the next HTTP hop is an origin server, including an
    /// originserver cache_peer. The three possible cases are:
    /// -# a direct TCP/HTTP connection to an origin server,
    /// -# a direct TCP/HTTP connection to an originserver cache_peer, and
    /// -# a CONNECT tunnel through a [non-originserver] cache_peer [to an origin server]
    /// Thus, toOrigin is false only when the HTTP request is sent over
    ///    a direct TCP/HTTP connection to a non-originserver cache_peer.
    bool toOrigin = false;

    /// Whether the next TCP/HTTP hop is an originserver cache_peer.
    bool toOriginPeer() const { return toOrigin && peering && !tunneling; }

    bool keepalive_broken = false;
    bool abuse_detected = false;
    bool request_sent = false;
    bool do_next_read = false;
    bool chunked = false;           ///< reading a chunked response; TODO: rename
    bool chunked_request = false;   ///< writing a chunked request
    bool sentLastChunk = false;     ///< do not try to write last-chunk again
};

} // namespace Http

#endif /* SQUID_SRC_HTTP_STATEFLAGS_H */

