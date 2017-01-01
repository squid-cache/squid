/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "comm.h"
#include "fatal.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <cstring>
#include <limits>

AnyP::PortCfgPointer HttpPortList;
#if USE_OPENSSL
AnyP::PortCfgPointer HttpsPortList;
#endif
AnyP::PortCfgPointer FtpPortList;

int NHttpSockets = 0;
int HttpSockets[MAXTCPLISTENPORTS];

AnyP::PortCfg::PortCfg() :
    next(),
    s(),
    transport(AnyP::PROTO_HTTP,1,1), // "Squid is an HTTP proxy", etc.
    name(NULL),
    defaultsite(NULL),
    flags(),
    allow_direct(false),
    vhost(false),
    actAsOrigin(false),
    ignore_cc(false),
    connection_auth_disabled(false),
    ftp_track_dirs(false),
    vport(0),
    disable_pmtu_discovery(0),
    listenConn()
#if USE_OPENSSL
    ,cert(NULL),
    key(NULL),
    version(0),
    cipher(NULL),
    options(NULL),
    clientca(NULL),
    cafile(NULL),
    capath(NULL),
    crlfile(NULL),
    dhfile(NULL),
    tls_dh(NULL),
    sslflags(NULL),
    sslContextSessionId(NULL),
    generateHostCertificates(false),
    dynamicCertMemCacheSize(std::numeric_limits<size_t>::max()),
    staticSslContext(),
    signingCert(),
    signPkey(),
    certsToChain(),
    untrustedSigningCert(),
    untrustedSignPkey(),
    clientVerifyCrls(),
    clientCA(),
    dhParams(),
    eecdhCurve(NULL),
    contextMethod(),
    sslContextFlags(0),
    sslOptions(0)
#endif
{
    memset(&tcp_keepalive, 0, sizeof(tcp_keepalive));
}

AnyP::PortCfg::~PortCfg()
{
    if (Comm::IsConnOpen(listenConn)) {
        listenConn->close();
        listenConn = NULL;
    }

    safe_free(name);
    safe_free(defaultsite);

#if USE_OPENSSL
    safe_free(cert);
    safe_free(key);
    safe_free(cipher);
    safe_free(options);
    safe_free(clientca);
    safe_free(cafile);
    safe_free(capath);
    safe_free(crlfile);
    safe_free(dhfile);
    safe_free(tls_dh);
    safe_free(sslflags);
    safe_free(sslContextSessionId);
    safe_free(eecdhCurve);
#endif
}

AnyP::PortCfgPointer
AnyP::PortCfg::clone() const
{
    AnyP::PortCfgPointer b = new AnyP::PortCfg();
    b->s = s;
    if (name)
        b->name = xstrdup(name);
    if (defaultsite)
        b->defaultsite = xstrdup(defaultsite);

    b->transport = transport;
    b->flags = flags;
    b->allow_direct = allow_direct;
    b->vhost = vhost;
    b->vport = vport;
    b->connection_auth_disabled = connection_auth_disabled;
    b->ftp_track_dirs = ftp_track_dirs;
    b->disable_pmtu_discovery = disable_pmtu_discovery;
    b->tcp_keepalive = tcp_keepalive;

#if USE_OPENSSL
    if (cert)
        b->cert = xstrdup(cert);
    if (key)
        b->key = xstrdup(key);
    b->version = version;
    if (cipher)
        b->cipher = xstrdup(cipher);
    if (options)
        b->options = xstrdup(options);
    if (clientca)
        b->clientca = xstrdup(clientca);
    if (cafile)
        b->cafile = xstrdup(cafile);
    if (capath)
        b->capath = xstrdup(capath);
    if (crlfile)
        b->crlfile = xstrdup(crlfile);
    if (dhfile)
        b->dhfile = xstrdup(dhfile);
    if (tls_dh)
        b->tls_dh = xstrdup(tls_dh);
    if (sslflags)
        b->sslflags = xstrdup(sslflags);
    if (sslContextSessionId)
        b->sslContextSessionId = xstrdup(sslContextSessionId);

#if 0
    // TODO: AYJ: 2015-01-15: for now SSL does not clone the context object.
    // cloning should only be done before the PortCfg is post-configure initialized and opened
    SSL_CTX *sslContext;
#endif

#endif /*0*/

    return b;
}

#if USE_OPENSSL
void
AnyP::PortCfg::configureSslServerContext()
{
    if (cert)
        Ssl::readCertChainAndPrivateKeyFromFiles(signingCert, signPkey, certsToChain, cert, key);

    if (!signingCert) {
        char buf[128];
        fatalf("No valid signing SSL certificate configured for %s_port %s", AnyP::ProtocolType_str[transport.protocol],  s.toUrl(buf, sizeof(buf)));
    }

    if (!signPkey)
        debugs(3, DBG_IMPORTANT, "No SSL private key configured for  " << AnyP::ProtocolType_str[transport.protocol] << "_port " << s);

    Ssl::generateUntrustedCert(untrustedSigningCert, untrustedSignPkey,
                               signingCert, signPkey);

    if (!untrustedSigningCert) {
        char buf[128];
        fatalf("Unable to generate signing SSL certificate for untrusted sites for %s_port %s", AnyP::ProtocolType_str[transport.protocol], s.toUrl(buf, sizeof(buf)));
    }

    if (crlfile)
        clientVerifyCrls.reset(Ssl::loadCrl(crlfile, sslContextFlags));

    if (clientca) {
        clientCA.reset(SSL_load_client_CA_file(clientca));
        if (clientCA.get() == NULL) {
            fatalf("Unable to read client CAs! from %s", clientca);
        }
    }

    contextMethod = Ssl::contextMethod(version);
    if (!contextMethod)
        fatalf("Unable to compute context method to use");

    const char *dhParamsFile = dhfile; // backward compatibility for dhparams= configuration
    safe_free(eecdhCurve); // clear any previous EECDH configuration
    if (tls_dh && *tls_dh) {
        eecdhCurve = xstrdup(tls_dh);
        char *p = strchr(eecdhCurve, ':');
        if (p) {  // tls-dh=eecdhCurve:dhParamsFile
            *p = '\0';
            dhParamsFile = p+1;
        } else {  // tls-dh=dhParamsFile
            dhParamsFile = tls_dh;
            // a NULL eecdhCurve means "do not use EECDH"
            safe_free(eecdhCurve);
        }
    }

    if (dhParamsFile && *dhParamsFile)
        dhParams.reset(Ssl::readDHParams(dhParamsFile));

    if (sslflags)
        sslContextFlags = Ssl::parse_flags(sslflags);

    sslOptions = Ssl::parse_options(options);

    staticSslContext.reset(sslCreateServerContext(*this));

    if (!staticSslContext) {
        char buf[128];
        fatalf("%s_port %s initialization error", AnyP::ProtocolType_str[transport.protocol],  s.toUrl(buf, sizeof(buf)));
    }
}
#endif

