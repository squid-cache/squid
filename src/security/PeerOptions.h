#ifndef SQUID_SRC_SECURITY_PEEROPTIONS_H
#define SQUID_SRC_SECURITY_PEEROPTIONS_H

#include "SBuf.h"

namespace Security
{

class PeerOptions
{
public:
    PeerOptions() : tls(false), ssl(false) {}

    bool tls;   ///< whether TLS is to be used on this connection
    bool ssl;   ///< whether SSL is to be used on this connection
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_PEEROPTIONS_H */
