/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ANYP_PORTCFG_H
#define SQUID_ANYP_PORTCFG_H

#include "anyp/forward.h"
#include "anyp/ProtocolVersion.h"
#include "anyp/TrafficMode.h"
#include "comm/Connection.h"
#include "sbuf/SBuf.h"
#include "security/ServerOptions.h"

#if USE_OPENSSL
#include "ssl/gadgets.h"
#endif

namespace AnyP
{

class PortCfg : public RefCountable
{
public:
    PortCfg();
    ~PortCfg();
    AnyP::PortCfgPointer clone() const;
#if USE_OPENSSL
    /// creates, configures, and validates SSL context and related port options
    void configureSslServerContext();
#endif

    PortCfgPointer next;

    Ip::Address s;
    AnyP::ProtocolVersion transport; ///< transport protocol and version received by this port
    char *name;                /* visible name */
    char *defaultsite;         /* default web site */

    TrafficMode flags;  ///< flags indicating what type of traffic to expect via this port.

    bool allow_direct;       ///< Allow direct forwarding in accelerator mode
    bool vhost;              ///< uses host header
    bool actAsOrigin;        ///< update replies to conform with RFC 2616
    bool ignore_cc;          ///< Ignore request Cache-Control directives

    bool connection_auth_disabled; ///< Don't support connection oriented auth

    bool ftp_track_dirs; ///< whether transactions should track FTP directories

    int vport;               ///< virtual port support. -1 if dynamic, >0 static
    int disable_pmtu_discovery;

    struct {
        unsigned int idle;
        unsigned int interval;
        unsigned int timeout;
        bool enabled;
    } tcp_keepalive;

    /**
     * The listening socket details.
     * If Comm::ConnIsOpen() we are actively listening for client requests.
     * use listenConn->close() to stop.
     */
    Comm::ConnectionPointer listenConn;

    /// TLS configuration options for this listening port
    Security::ServerOptions secure;

#if USE_OPENSSL
    char *clientca;
    char *sslContextSessionId; ///< "session id context" for secure.staticSslContext
    bool generateHostCertificates; ///< dynamically make host cert for sslBump
    size_t dynamicCertMemCacheSize; ///< max size of generated certificates memory cache

    Security::CertPointer signingCert; ///< x509 certificate for signing generated certificates
    Ssl::EVP_PKEY_Pointer signPkey; ///< private key for sighing generated certificates
    Ssl::X509_STACK_Pointer certsToChain; ///<  x509 certificates to send with the generated cert
    Security::CertPointer untrustedSigningCert; ///< x509 certificate for signing untrusted generated certificates
    Ssl::EVP_PKEY_Pointer untrustedSignPkey; ///< private key for signing untrusted generated certificates

    Ssl::X509_NAME_STACK_Pointer clientCA; ///< CA certificates to use when verifying client certificates
#endif
};

} // namespace AnyP

/// list of Squid http(s)_port configured
extern AnyP::PortCfgPointer HttpPortList;

/// list of Squid ftp_port configured
extern AnyP::PortCfgPointer FtpPortList;

#if !defined(MAXTCPLISTENPORTS)
// Max number of TCP listening ports
#define MAXTCPLISTENPORTS 128
#endif

// TODO: kill this global array. Need to check performance of array vs list though.
extern int NHttpSockets;
extern int HttpSockets[MAXTCPLISTENPORTS];

#endif /* SQUID_ANYP_PORTCFG_H */

