/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_SERVEROPTIONS_H
#define SQUID_SRC_SECURITY_SERVEROPTIONS_H

#include "security/PeerOptions.h"

namespace Security
{

/// TLS squid.conf settings for a listening port
class ServerOptions : public PeerOptions
{
public:
    ServerOptions() : PeerOptions() {}
    explicit ServerOptions(const Security::ServerOptions &);
    virtual ~ServerOptions() = default;

    /* Security::PeerOptions API */
    virtual void parse(const char *);
    virtual void clear() {*this = ServerOptions();}
    virtual void dumpCfg(Packable *, const char *pfx) const;

    /// update the context with DH, EDH, EECDH settings
    void updateContextEecdh(Security::ContextPointer &);

private:
    void loadDhParams();

//public:
    SBuf dh;            ///< Diffi-Helman cipher config

private:
    SBuf dhParamsFile;  ///< Diffi-Helman ciphers parameter file
    SBuf eecdhCurve;    ///< Elliptic curve for ephemeral EC-based DH key exchanges

    Security::DhePointer parsedDhParams; ///< DH parameters for temporary/ephemeral DH key exchanges
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SERVEROPTIONS_H */

