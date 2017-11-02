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
#if USE_OPENSSL
    sk_dtor_wrapper(sk_X509_NAME, STACK_OF(X509_NAME) *, X509_NAME_free);
    typedef std::unique_ptr<STACK_OF(X509_NAME), Security::ServerOptions::sk_X509_NAME_free_wrapper> X509_NAME_STACK_Pointer;
#endif

    ServerOptions() : PeerOptions() {
        // Bug 4005: dynamic contexts use a lot of memory and it
        // is more secure to have only a small set of trusted CA.
        flags.tlsDefaultCa.defaultTo(false);
    }
    ServerOptions(const ServerOptions &) = default;
    ServerOptions &operator =(const ServerOptions &);
    ServerOptions(ServerOptions &&o) { this->operator =(o); }
    ServerOptions &operator =(ServerOptions &&o) { this->operator =(o); return *this; }
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

    /// initialize contexts for signing dynamic TLS certificates (if needed)
    /// the resulting context is stored in signingCert, signPKey, untrustedSigningCert, untrustedSignPKey
    void createSigningContexts(AnyP::PortCfg &);

    /// update the given TLS security context using squid.conf settings
    bool updateContextConfig(Security::ContextPointer &);

    /// update the context with DH, EDH, EECDH settings
    void updateContextEecdh(Security::ContextPointer &);

    /// update the context with CA details used to verify client certificates
    void updateContextClientCa(Security::ContextPointer &);

    /// update the context with a configured session ID (if any)
    void updateContextSessionId(Security::ContextPointer &);

    /// sync the various sources of CA files to be loaded
    void syncCaFiles();

public:
    /// TLS context to use for HTTPS accelerator or static SSL-Bump
    Security::ContextPointer staticContext;
    SBuf staticContextSessionId; ///< "session id context" for staticContext

    bool generateHostCertificates = true; ///< dynamically make host cert

    Security::CertPointer signingCert; ///< x509 certificate for signing generated certificates
    Security::PrivateKeyPointer signPkey; ///< private key for signing generated certificates
    Security::CertList certsToChain; ///<  x509 certificates to send with the generated cert
    Security::CertPointer untrustedSigningCert; ///< x509 certificate for signing untrusted generated certificates
    Security::PrivateKeyPointer untrustedSignPkey; ///< private key for signing untrusted generated certificates

    /// max size of generated certificates memory cache (4 MB default)
    size_t dynamicCertMemCacheSize = 4*1024*1024;

private:
    bool loadClientCaFile();
    void loadDhParams();

private:
    SBuf clientCaFile;  ///< name of file to load client CAs from
#if USE_OPENSSL
    /// CA certificate(s) to use when verifying client certificates
    X509_NAME_STACK_Pointer clientCaStack;
#else
    void *clientCaStack = nullptr;
#endif

    SBuf dh;            ///< Diffi-Helman cipher config
    SBuf dhParamsFile;  ///< Diffi-Helman ciphers parameter file
    SBuf eecdhCurve;    ///< Elliptic curve for ephemeral EC-based DH key exchanges

    Security::DhePointer parsedDhParams; ///< DH parameters for temporary/ephemeral DH key exchanges
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_SERVEROPTIONS_H */

