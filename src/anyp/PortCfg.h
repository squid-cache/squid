#ifndef SQUID_ANYP_PORTCFG_H
#define SQUID_ANYP_PORTCFG_H

#include "cbdata.h"
#include "comm/Connection.h"

#if USE_SSL
#include "ssl/gadgets.h"
#endif

namespace AnyP
{

class PortCfg
{
public:
    PortCfg(const char *aProtocol);
    ~PortCfg();
    AnyP::PortCfg *clone() const;
#if USE_SSL
    /// creates, configures, and validates SSL context and related port options
    void configureSslServerContext();
#endif

    PortCfg *next;

    Ip::Address s;
    char *protocol;            /* protocol name */
    char *name;                /* visible name */
    char *defaultsite;         /* default web site */

    unsigned int intercepted:1;        /**< intercepting proxy port */
    unsigned int spoof_client_ip:1;    /**< spoof client ip if possible */
    unsigned int accel:1;              /**< HTTP accelerator */
    unsigned int allow_direct:1;       /**< Allow direct forwarding in accelerator mode */
    unsigned int vhost:1;              /**< uses host header */
    unsigned int sslBump:1;            /**< intercepts CONNECT requests */
    unsigned int actAsOrigin:1;        ///< update replies to conform with RFC 2616
    unsigned int ignore_cc:1;          /**< Ignore request Cache-Control directives */

    int vport;                 /* virtual port support, -1 for dynamic, >0 static*/
    bool connection_auth_disabled;     /* Don't support connection oriented auth */
    int disable_pmtu_discovery;

    struct {
        unsigned int enabled;
        unsigned int idle;
        unsigned int interval;
        unsigned int timeout;
    } tcp_keepalive;

    /**
     * The listening socket details.
     * If Comm::ConnIsOpen() we are actively listening for client requests.
     * use listenConn->close() to stop.
     */
    Comm::ConnectionPointer listenConn;

#if USE_SSL
    char *cert;
    char *key;
    int version;
    char *cipher;
    char *options;
    char *clientca;
    char *cafile;
    char *capath;
    char *crlfile;
    char *dhfile;
    char *sslflags;
    char *sslContextSessionId; ///< "session id context" for staticSslContext
    bool generateHostCertificates; ///< dynamically make host cert for sslBump
    size_t dynamicCertMemCacheSize; ///< max size of generated certificates memory cache

    Ssl::SSL_CTX_Pointer staticSslContext; ///< for HTTPS accelerator or static sslBump
    Ssl::X509_Pointer signingCert; ///< x509 certificate for signing generated certificates
    Ssl::EVP_PKEY_Pointer signPkey; ///< private key for sighing generated certificates
    Ssl::X509_STACK_Pointer certsToChain; ///<  x509 certificates to send with the generated cert
    Ssl::X509_Pointer untrustedSigningCert; ///< x509 certificate for signing untrusted generated certificates
    Ssl::EVP_PKEY_Pointer untrustedSignPkey; ///< private key for signing untrusted generated certificates

    Ssl::X509_CRL_STACK_Pointer clientVerifyCrls; ///< additional CRL lists to use when verifying the client certificate
    Ssl::X509_NAME_STACK_Pointer clientCA; ///< CA certificates to use when verifying client certificates
    Ssl::DH_Pointer dhParams; ///< DH parameters for temporary/ephemeral DH key exchanges
    Ssl::ContextMethod contextMethod; ///< The context method (SSL_METHOD) to use when creating certificates
    long sslContextFlags; ///< flags modifying the use of SSL
    long sslOptions; ///< SSL engine options
#endif

    CBDATA_CLASS2(PortCfg); // namespaced
};

} // namespace AnyP

// Max number of TCP listening ports
#define MAXTCPLISTENPORTS 128

// TODO: kill this global array. Need to check performance of array vs list though.
extern int NHttpSockets;
extern int HttpSockets[MAXTCPLISTENPORTS];

#endif /* SQUID_ANYP_PORTCFG_H */
