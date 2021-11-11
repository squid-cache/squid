/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_TWO_FRAME_H
#define _SQUID_SRC_HTTP_TWO_FRAME_H

namespace Http
{
namespace Two
{

/* RFC 7540 section 4.1 */

/// Bit layout for HTTP/2 frame header
struct FrameHeader {
    /* fun with bit-alignment, means lots of magic numbers:
     * length    : 24
     * type      : 8
     * flags     : 8
     * reserved  : 1
     * stream-id : 31
     */
    uint8_t data[9] = {0,0,0,0,0,0,0,0,0}; // 9 octets (+ some compiler padding which we ignore.)

    uint32_t length() const {
        return (data[0] << 16) +
               (data[1] << 8) +
               data[2];
    }
    void length(uint32_t L) {
        for (int i = 2; i >= 0; --i) {
            data[i] = (L & 0xFF); L = L >> 8;
        }
    }

    uint8_t type() const {return data[3];}
    void type(uint8_t T) {data[3] = T;}

    uint8_t flags() const {return data[4];}
    void flags(uint8_t F) {data[4] = F;}

    uint32_t streamId() const {
        return (data[5] << 24) +
               (data[6] << 16) +
               (data[7] << 8) +
               data[8];
    }
    void streamId(uint32_t S) {
        for (int i = 8; i >= 5; --i) {
            data[i] = (S & 0xFF); S = S >> 8;
        }
    }
};

static_assert(sizeof(struct FrameHeader) == 9, "sizeof(struct FrameHeader) == 9");

// frame size boundaries are connection-specific, but there are
// some universal limits in RFC 7540 section 4.2

// MUST be capable of... frames up to 2^14 octets in length
const static uint32_t MaxFramePayloadSz = (1<<14);

// ... plus the 9 octet frame header
const static uint32_t MaxFrameDefaultSz = MaxFramePayloadSz + 9;

// SETTINGS_MAX_FRAME_SIZE may extend frame size up to 2^24-1
const static uint32_t MaxFrameExtendedSz = (1<<24)-1;

/// HTTP/2 frame flags field values
/// RFC 7540 sections 6.1 - 6.10
enum FrameFlags {
    // flag 1 only ('bit 0') has frame specific naming,
    // but the semantic meaning remains essentially the same
    FLAG_END_STREAM     = 0x1,
    FLAG_ACK            = FLAG_END_STREAM,
    // reserved 0x2
    FLAG_END_HEADERS    = 0x4,
    FLAG_PADDED         = 0x8,
    // reserved 0x10
    FLAG_PRIORITY       = 0x20
    // reserved 0x40
    // reserved 0x80
};

} // namespace Two
} // namespace Http

#endif /* _SQUID_SRC_HTTP_TWO_FRAME_H */
