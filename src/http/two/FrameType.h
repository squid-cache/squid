/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_TWO_FRAMETYPE_H
#define _SQUID_SRC_HTTP_TWO_FRAMETYPE_H

namespace Http
{
namespace Two
{

/// HTTP/2 Frame Type registrations
enum FrameType {
    /* RFC 7540 section 11.2 */
    DATA          = 0x00,
    HEADERS       = 0x01,
    PRIORITY      = 0x02,
    RST_STREAM    = 0x03,
    SETTINGS      = 0x04,
    PUSH_PROMISE  = 0x05,
    PING          = 0x06,
    GOAWAY        = 0x07,
    WINDOW_UPDATE = 0x08,
    CONTINUATION  = 0x09,

    /* RFC 7838 section 4 */
    ALTSVC        = 0x0A,

    /* RFC 8336 section 2.1 */
    ORIGIN        = 0x0C

    /* types 0xf0-0xff reserved for experimental use */
};

} // namespace Two
} // namespace Http

#endif /* _SQUID_SRC_HTTP_TWO_FRAMETYPE_H */
