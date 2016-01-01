/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

/**
 * Stores HTTP version label information.
 *
 * Squid being conditionally compliant with RFC 2616
 * on both client and server connections the default
 * value is HTTP/1.1.
 */
class ProtocolVersion : public AnyP::ProtocolVersion
{
public:
    ProtocolVersion() : AnyP::ProtocolVersion(AnyP::PROTO_HTTP,1,1) {}

    ProtocolVersion(unsigned int aMajor, unsigned int aMinor) : AnyP::ProtocolVersion(AnyP::PROTO_HTTP,aMajor,aMinor) {}
};

}; // namespace Http

#endif /* SQUID_HTTP_PROTOCOLVERSION_H */

