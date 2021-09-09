/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_QUIC_FORWARD_H
#define _SQUID__SRC_QUIC_FORWARD_H

/* DEBUG: section 94    QUIC Protocol */

/// QUIC Protocol
namespace Quic
{

/// RFC 8999 mask for extracting the QUIC packet type flag (bit 0)
#define QUIC_PACKET_TYPE_MASK 0x80

/// RFC 8999 section 5.4 reserved version value */
#define QUIC_VERSION_NEGOTIATION 0x00000000

/// RFC 9000 section 15 reserved version values.
/// Any packet received with one of these versions must be ignored or
/// responded to using RFC 8999 section 6 Version Negotiation process.
#define QUIC_VERSION_FORCE_NEGOTIATE_MASK  ntohl(0x0A0A0A0A)

/// RFC 9000 section 17.2 flag to indicating valid packets (bit 1)
#define QUIC_RFC9000_PACKET_VALID 0x40

/// RFC 9000 section 17.2 mask for extracting the QUIC packet-type (bits 2-3)
#define QUIC_RFC9000_PTYPE 0x30

/// RFC 9000 section 17.2 mask for extracting the QUIC type-specific bits (bits 4-7)
#define QUIC_RFC9000_PTYPE_BITS 0x0F

class Connection;

} // namespace Quic

#endif /* _SQUID__SRC_QUIC_FORWARD_H */

