/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_QUIC_CONNECTION_H
#define _SQUID__SRC_QUIC_CONNECTION_H

#include "ip/Address.h"
#include "quic/forward.h"
#include "sbuf/SBuf.h"

namespace Quic
{

/**
 * QUIC Protocol connection 'tuplet'
 *
 * A connection in QUIC is represented by src and dst IDs, QUIC version
 * and possibly some version-specific flags.
 * The later two details define which version specific syntax and
 * semantics are used within the QUIC packet data.
 *
 * see RFC 8999 section 5
 */
class Connection : public RefCountable
{
public:
    /// IP:port of client this packet was received from
    Ip::Address clientAddress;

    /// Packet Type flag (1),
    /// Version-Specific Bits (7),
    uint8_t vsBits = 0;

    /// Version (32),
    uint32_t version = QUIC_VERSION_NEGOTIATION;

    /// Destination Connection ID (0..2040),
    SBuf dstConnectionId;

    /// Source Connection ID (0..2040),
    SBuf srcConnectionId;
};

inline uint64_t
MemoryUsedByConnection(const Quic::ConnectionPointer &c)
{
    return uint64_t(sizeof(c)) + c->srcConnectionId.length() + c->dstConnectionId.length();
}

} // namespace Quic

#endif /* _SQUID__SRC_QUIC_CONNECTION_H */

