/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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
    bool keepalive = false;
    bool only_if_cached = false;
    bool handling1xx = false;       ///< we are ignoring or forwarding 1xx response
    bool headers_parsed = false;

    /* these three flags describe the next TCP hop */
    // XXX: .toOrigin is !.toProxy
    // TODO: confirm that .peering is needed or use _peer instead
    bool toOrigin = false; ///< an origin server or originserver cache_peer
    bool toProxy = false; ///< a non-originserver cache_peer
    bool peering = false; ///< any cache_peer, including originserver

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

