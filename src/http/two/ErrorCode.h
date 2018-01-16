/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_TWO_ERRORCODE_H
#define _SQUID_SRC_HTTP_TWO_ERRORCODE_H

#include "http/forward.h"

#include <ostream>

namespace Http
{
namespace Two
{

/// HTTP/2 Error Code registrations
enum ErrorCode {
    /* RFC 7540 section 11.4 */
    NO_ERROR            = 0x0,
    PROTOCOL_ERROR      = 0x1,
    INTERNAL_ERROR      = 0x2,
    FLOW_CONTROL_ERROR  = 0x3,
    SETTINGS_TIMEOUT    = 0x4,
    STREAM_CLOSED       = 0x5,
    FRAME_SIZE_ERROR    = 0x6,
    REFUSED_STREAM      = 0x7,
    CANCEL              = 0x8,
    COMPRESSION_ERROR   = 0x9,
    CONNECT_ERROR       = 0xa,
    ENHANCE_YOUR_CALM   = 0xb,
    INADEQUATE_SECURITY = 0xc,
    HTTP_1_1_REQUIRED   = 0xd
};

} // namespace Two

/// Textual representation of the HTTP/2 error code
std::ostream &operator <<(std::ostream &, const Http2::ErrorCode &e);

} // namespace Http

#endif /* _SQUID_SRC_HTTP_TWO_ERRORCODE_H */
