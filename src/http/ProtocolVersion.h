/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_PROTOCOLVERSION_H
#define SQUID_HTTP_PROTOCOLVERSION_H

#include "anyp/ProtocolVersion.h"

namespace Http
{

/// HTTP version label information
inline AnyP::ProtocolVersion
ProtocolVersion(unsigned int aMajor, unsigned int aMinor)
{
    return AnyP::ProtocolVersion(AnyP::PROTO_HTTP,aMajor,aMinor);
}

/**
 * HTTP version label information.
 *
 * Squid being conditionally compliant with RFC 7230
 * on both client and server connections the default
 * value is HTTP/1.1.
 */
inline AnyP::ProtocolVersion
ProtocolVersion()
{
    return AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1);
}

}; // namespace Http

#endif /* SQUID_HTTP_PROTOCOLVERSION_H */

