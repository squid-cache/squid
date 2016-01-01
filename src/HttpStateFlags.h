/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPSTATEFLAGS_H_
#define SQUID_HTTPSTATEFLAGS_H_

// POD
class HttpStateFlags
{
public:
    bool proxying:1;
    bool keepalive:1;
    bool only_if_cached:1;
    bool handling1xx:1; ///< we are ignoring or forwarding 1xx response
    bool headers_parsed:1;
    unsigned int front_end_https:2; //XXX: huh?
    bool originpeer:1;
    bool keepalive_broken:1;
    bool abuse_detected:1;
    bool request_sent:1;
    bool do_next_read:1;
    bool consume_body_data:1; //XXX: seems unused
    bool chunked:1; ///< reading a chunked response; TODO: rename
    bool chunked_request:1; ///< writing a chunked request
    bool sentLastChunk:1; ///< do not try to write last-chunk again
};

#endif /* SQUID_HTTPSTATEFLAGS_H_ */

