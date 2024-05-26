/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_FRAMETYPE_H
#define SQUID_SRC_HTTP_FRAMETYPE_H

#include "sbuf/SBuf.h"

namespace Http
{

/// HTTP Frame Type registrations
typedef enum : uint8_t {
    /* RFC 9113 section 6.1 */
    FRAME_DATA          = 0x00,
    FRAME_HEADERS       = 0x01,
    FRAME_PRIORITY      = 0x02,
    FRAME_RST_STREAM    = 0x03,
    FRAME_SETTINGS      = 0x04,
    FRAME_PUSH_PROMISE  = 0x05,
    FRAME_PING          = 0x06,
    FRAME_GOAWAY        = 0x07,
    FRAME_WINDOW_UPDATE = 0x08,
    FRAME_CONTINUATION  = 0x09,

    /* RFC 7838 section 4 */
    FRAME_ALTSVC        = 0x0A,

    /* RFC 8336 section 2.1 */
    FRAME_ORIGIN        = 0x0C,

    /* RFC 9114 section 7.2 */
    FRAME_CANCEL_PUSH   = FRAME_RST_STREAM,
    FRAME_MAX_PUSH_ID   = 0x0D

    /* types 0x1f * N + 0x21 reserved for experimental use */
    /* types 0xf0-0xff reserved for experimental use */
} FrameType;

extern const SBuf FrameType_sb[];

inline const SBuf &
FrameTypeStr(const FrameType m)
{
    return FrameType_sb[m];
}

} // namespace Http

#endif /* SQUID_SRC_HTTP_FRAMETYPE_H */
