/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_PEEROPTIONS_H
#define SQUID_SRC_SECURITY_PEEROPTIONS_H

#include "base/YesNoNone.h"
#include "ConfigParser.h"
#include "security/KeyData.h"

class Packable;

namespace Security
{

/// TLS squid.conf settings for a remote server peer
class PeerOptions
{
public:
    PeerOptions() : parsedOptions(0), parsedFlags(0), sslVersion(0), encryptTransport(false) {}
    PeerOptions(const PeerOptions &);
    virtual ~PeerOptions() = default;

    /// parse a TLS squid.conf option
    virtual void parse(const char *);

    /// reset the configuration details to default
    virtual void clear() {*this = PeerOptions();}

    /// generate an unset security context object
    virtual Security::ContextPointer createBlankContext() const;

    /// generate a security client-context from these configured options
    Security::ContextPointer createClientContext(bool setOptions);

    /// sync the context options with tls-min-version=N configuration
    void updateTlsVersionLimits();

    /// setup the NPN extension details for the given context
    void updateContextNpn(Security::ContextPointer &);

    /// setup the CA details for the given context
    void updateContextCa(Security::ContextPointer &);

    /// setup the CRL details for the given context
    void updateContextCrl(Security::ContextPointer &);

    /// output squid.conf syntax with 'pfx' prefix on parameters for the stored settings
    virtual void dumpCfg(Packable *, const char *pfx) const;

private:
    long parseOptions();
    long parseFlags();
    void loadCrlFile();

public:
    SBuf sslOptions;     ///< library-specific options string
    SBuf caDir;          ///< path of directory containing a set of trusted Certificate Authorities
    SBuf crlFile;        ///< path of file containing Certificate Revoke List

    SBuf sslCipher;
    SBuf sslFlags;       ///< flags defining what TLS operations Squid performs
    SBuf sslDomain;

    SBuf tlsMinVersion;  ///< version label for minimum TLS version to permit

    long parsedOptions; ///< parsed value of sslOptions
    long parsedFlags;   ///< parsed value of sslFlags

    std::list<Security::KeyData> certs; ///< details from the cert= and file= config parameters
    std::list<SBuf> caFiles;  ///< paths of files containing trusted Certificate Authority
    Security::CertRevokeList parsedCrl; ///< CRL to use when verifying the remote end certificate

protected:
    int sslVersion;

    /// flags governing Squid internal TLS operations
    struct flags_ {
        flags_() : tlsDefaultCa(true), tlsNpn(true) {}

        /// whether to use the system default Trusted CA when verifying the remote end certificate
        YesNoNone tlsDefaultCa;

        /// whether to use the TLS NPN extension on these connections
        bool tlsNpn;
    } flags;

public:
    /// whether transport encryption (TLS/SSL) is to be used on connections to the peer
    bool encryptTransport;
};

/// configuration options for DIRECT server access
extern PeerOptions ProxyOutgoingConfig;

} // namespace Security

// parse the tls_outgoing_options directive
void parse_securePeerOptions(Security::PeerOptions *);
#define free_securePeerOptions(x) Security::ProxyOutgoingConfig.clear()
#define dump_securePeerOptions(e,n,x) do { (e)->appendf(n); (x).dumpCfg((e),""); (e)->append("\n",1); } while(false)

#endif /* SQUID_SRC_SECURITY_PEEROPTIONS_H */

