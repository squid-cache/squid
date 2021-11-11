/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_TWO_STREAM_H
#define _SQUID_SRC_HTTP_TWO_STREAM_H

#include "http/two/forward.h"

namespace Http
{
namespace Two
{

/* RFC 7540 section 5.1 */

/// HTTP/2 stream states
enum StreamState {
    IDLE = 0x0,      ///< no frames seen for this stream
    RESERVED_LOCAL,  ///< has been promised by sending a PUSH_PROMISE frame
    RESERVED_REMOTE, ///< has been reserved by a remote peer
    OPEN,            ///< may be used by both peers to send frames of any type
    CLOSED_LOCAL,    ///< cannot be used for sending frames
    CLOSED_REMOTE,   ///< no longer being used by the peer to send frames
    CLOSED           ///< terminal state
};

/* RFC 7540 section 5.1.1 */

// stream ID boundaries
const static uint32_t ControlStreamId = 0x0;      ///< control message frame
const static uint32_t MinStreamId = 0x00000001;   ///< 1 (stream 0 is reserved for control frames)
const static uint32_t MaxStreamId = 0x7FFFFFFF;   ///< 2^31-1

} // namespace Two
} // namespace Http

#endif /* _SQUID_SRC_HTTP_STREAM_H */
