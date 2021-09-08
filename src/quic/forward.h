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

// TODO: implement RFC 8999 section 6 QUIC version negotiation

class Connection;

} // namespace Quic

#endif /* _SQUID__SRC_QUIC_FORWARD_H */

