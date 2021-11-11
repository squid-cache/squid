/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_TWO_STREAMCONTEXT_H
#define _SQUID_SRC_HTTP_TWO_STREAMCONTEXT_H

#include "BodyPipe.h"
#include "http/two/forward.h"
#include "http/two/StreamState.h"
#include "mem/forward.h"
#include "sbuf/List.h"

namespace Http
{
namespace Two
{

/**
 * The state context for an HTTP/2 stream
 */
class StreamContext : public RefCountable
{
    MEMPROXY_CLASS(StreamContext);

public:
    StreamContext() : id(0) {}

    /// update this context with new state from the given parser
    void update(const Http2::FrameParserPointer &);

    /// per-connection ID used to identify traffic for this stream
    /// amidst the other multiplexed streams being transferred.
    uint32_t id;

    /// what state this streams is currently in.
    Http2::StreamState state;

    /// payload of HEADERS frame.
    /// TODO store decompressed form instead of compressed.
    SBuf headers;

    /// queue of frames waiting to be written
    SBufList writeQueue;

    /// set when we are reading request body/payload
    BodyPipe::Pointer inDataPipe;
};

} // namespace Two
} // namespace Http

#endif /* _SQUID_SRC_HTTP_TWO_STREAMCONTEXT_H */
