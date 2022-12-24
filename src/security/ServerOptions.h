/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_SERVEROPTIONS_H
#define SQUID_SRC_SECURITY_SERVEROPTIONS_H

#include "anyp/forward.h"
#include "security/PeerOptions.h"
#if USE_OPENSSL
#include "compat/openssl.h"
#if HAVE_OPENSSL_X509_H
#include <openssl/x509.h>
#endif
#endif

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
    ServerOptions(const ServerOptions &o): ServerOptions() { *this = o; }
    ServerOptions &operator =(const ServerOptions &);
    ServerOptions(ServerOptions &&o) { this->operator =(o); }
    ServerOptions &operator =(ServerOptions &&o) { this->operator =(o); return *this; }
    virtual ~ServerOptions() = default;

    /* Security::PeerOptions API */
    virtual void parse(const char *);
    virtual void clear() {*this = ServerOptions();}
    virtual Security::ContextPointer createBlankContext() const;
    virtual void dumpCfg(Packable *, const char *pfx) const;

    /// initialize all server contexts as-needed and load PEM files.
    /// if none can be created this may do nothing.
    void initServerContexts(AnyP::PortCfg &);

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

#if USE_OPENSSL
    bool generateHostCertificates = true; ///< dynamically make host cert
#elif USE_GNUTLS
    // TODO: GnuTLS does implement TLS server connections so the cert
    // generate vs static choice can be reached in the code now.
    // But this feature is not fully working implemented so must not
    // be enabled by default for production installations.
    bool generateHostCertificates = false; ///< dynamically make host cert
#else
    // same as OpenSSL so config errors show up easily
    bool generateHostCertificates = true; ///< dynamically make host cert
#endif

    Security::KeyData signingCa; ///< x509 certificate and key for signing generated certificates
    Security::KeyData untrustedSigningCa; ///< x509 certificate and key for signing untrusted generated certificates

    /// max size of generated certificates memory cache (4 MB default)
    size_t dynamicCertMemCacheSize = 4*1024*1024;

private:
    bool loadClientCaFile();
    void loadDhParams();

    /// generate a security server-context from these configured options
    /// the resulting context is stored in staticContext
    /// \returns true if a context could be created
    bool createStaticServerContext(AnyP::PortCfg &);

    /// initialize contexts for signing dynamic TLS certificates (if needed)
    /// the resulting keys are stored in signingCa and untrustedSigningCa
    void createSigningContexts(const AnyP::PortCfg &);

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

