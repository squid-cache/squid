/*
 * $Id$
 */
#ifndef SQUID_PROTO_PORT_H
#define SQUID_PROTO_PORT_H

//#include "typedefs.h"
#include "cbdata.h"
#if USE_SSL
#include "ssl/gadgets.h"
#endif

struct http_port_list {
    http_port_list(const char *aProtocol);
    ~http_port_list();

    http_port_list *next;

    IpAddress s;
    char *protocol;            /* protocol name */
    char *name;                /* visible name */
    char *defaultsite;         /* default web site */

    unsigned int intercepted:1;        /**< intercepting proxy port */
    unsigned int spoof_client_ip:1;    /**< spoof client ip if possible */
    unsigned int accel:1;              /**< HTTP accelerator */
    unsigned int allow_direct:1;       /**< Allow direct forwarding in accelerator mode */
    unsigned int vhost:1;              /**< uses host header */
    unsigned int sslBump:1;            /**< intercepts CONNECT requests */
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

#if USE_SSL
    // XXX: temporary hack to ease move of SSL options to http_port
    http_port_list &http;

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
#endif

    CBDATA_CLASS2(http_port_list);
};


#if USE_SSL

struct https_port_list: public http_port_list {
    https_port_list();
};

#endif

#endif /* SQUID_PROTO_PORT_H */
