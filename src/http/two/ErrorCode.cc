/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "http/two/ErrorCode.h"
#include "sbuf/SBuf.h"

namespace Http {
namespace Two {

struct ErrorCodeDesc
{
    Http2::ErrorCode code;
    SBuf label;
    SBuf description;
};

static const struct ErrorCodeDesc ErrorCode_str[] = {
        { Http2::NO_ERROR, SBuf("NO_ERROR"), SBuf("Graceful shutdown") },
        { Http2::PROTOCOL_ERROR, SBuf("PROTOCOL_ERROR"), SBuf("Protocol error detected") },
        { Http2::INTERNAL_ERROR, SBuf("INTERNAL_ERROR"), SBuf("Implementation fault") },
        { Http2::FLOW_CONTROL_ERROR, SBuf("FLOW_CONTROL_ERROR"), SBuf("Flow control limits exceeded") },
        { Http2::SETTINGS_TIMEOUT, SBuf("SETTINGS_TIMEOUT"), SBuf("Settings not acknowledged") },
        { Http2::STREAM_CLOSED, SBuf("STREAM_CLOSED"), SBuf("Frame received for closed stream") },
        { Http2::FRAME_SIZE_ERROR, SBuf("FRAME_SIZE_ERROR"), SBuf("Frame size incorrect") },
        { Http2::REFUSED_STREAM, SBuf("REFUSED_STREAM"), SBuf("Stream not processed") },
        { Http2::CANCEL, SBuf("CANCEL"), SBuf("Stream cancelled") },
        { Http2::COMPRESSION_ERROR, SBuf("COMPRESSION_ERROR"), SBuf("Compression state not updated") },
        { Http2::CONNECT_ERROR, SBuf("CONNECT_ERROR"), SBuf("TCP connection error for CONNECT method") },
        { Http2::ENHANCE_YOUR_CALM, SBuf("ENHANCE_YOUR_CALM"), SBuf("Processing capacity exceeded") },
        { Http2::INADEQUATE_SECURITY, SBuf("INADEQUATE_SECURITY"), SBuf("Negotiated TLS parameters not acceptable") },
        { Http2::HTTP_1_1_REQUIRED, SBuf("HTTP_1_1_REQUIRED"), SBuf("Use HTTP/1.1 for the request") }
    };

} // namespace Two
} // namespace Http

std::ostream &
Http::operator <<(std::ostream &os, const Http2::ErrorCode &e)
{
    if (e > Http2::HTTP_1_1_REQUIRED)
        os << "UNDEFINED ERROR";
    else
        os << Http2::ErrorCode_str[e].label << " (" << Http2::ErrorCode_str[e].description << ")";
    return os;
}
