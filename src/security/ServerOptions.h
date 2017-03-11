/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_SERVEROPTIONS_H
#define SQUID_SRC_SECURITY_SERVEROPTIONS_H

#include "anyp/forward.h"
#include "security/PeerOptions.h"

namespace Security
{

/// TLS squid.conf settings for a listening port
class ServerOptions : public PeerOptions
{
public:
    ServerOptions() : PeerOptions() {
        // Bug 4005: dynamic contexts use a lot of memory and it
        // is more secure to have only a small set of trusted CA.
        flags.tlsDefaultCa.defaultTo(false);
    }
    ServerOptions(const ServerOptions &) = default;
    ServerOptions &operator =(const ServerOptions &) = default;
    ServerOptions(ServerOptions &&) = default;
    ServerOptions &operator =(ServerOptions &&) = default;
    virtual ~ServerOptions() = default;

    /* Security::PeerOptions API */
    virtual void parse(const char *);
    virtual void clear() {*this = ServerOptions();}
    virtual Security::ContextPointer createBlankContext() const;
    virtual void dumpCfg(Packable *, const char *pfx) const;

    /// generate a security server-context from these configured options
    /// the resulting context is stored in staticContext
    /// \returns true if a context could be created
    bool createStaticServerContext(AnyP::PortCfg &);

    /// update the context with DH, EDH, EECDH settings
    void updateContextEecdh(Security::ContextPointer &);

public:
    /// TLS context to use for HTTPS accelerator or static SSL-Bump
    Security::ContextPointer staticContext;

private:
    void loadDhParams();

private:
    SBuf dh;            ///< Diffi-Helman cipher config
    SBuf dhParamsFile;  ///< Diffi-Helman ciphers parameter file
    SBuf eecdhCurve;    ///< Elliptic curve for ephemeral EC-based DH key exchanges

    Security::DhePointer parsedDhParams; ///< DH parameters for temporary/ephemeral DH key exchanges
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SERVEROPTIONS_H */

