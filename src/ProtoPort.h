/*
 * $Id$
 */
#ifndef SQUID_PROTO_PORT_H
#define SQUID_PROTO_PORT_H

//#include "typedefs.h"
#include "cbdata.h"

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
    char *sslcontext;
    SSL_CTX *sslContext;
#endif

    CBDATA_CLASS2(http_port_list);
};


#if USE_SSL

struct https_port_list: public http_port_list {
    https_port_list();
};

#endif

#endif /* SQUID_PROTO_PORT_H */
