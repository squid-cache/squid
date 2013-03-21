#ifndef SQUID_HTTP_PROTOCOLVERSION_H
#define SQUID_HTTP_PROTOCOLVERSION_H

#include "anyp/ProtocolVersion.h"

namespace Http
{

/**
 * Stores HTTP version label information.
 * For example HTTP/1.0
 */
class ProtocolVersion : public AnyP::ProtocolVersion
{
public:
    ProtocolVersion() : AnyP::ProtocolVersion(AnyP::PROTO_HTTP,0,0) {}

    ProtocolVersion(unsigned int aMajor, unsigned int aMinor) : AnyP::ProtocolVersion(AnyP::PROTO_HTTP,aMajor,aMinor) {}
};

}; // namespace Http

#endif /* SQUID_HTTP_PROTOCOLVERSION_H */
