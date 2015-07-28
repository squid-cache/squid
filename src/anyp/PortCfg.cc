/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "comm.h"
#include "fatal.h"
#include "security/PeerOptions.h"
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
    ,
    clientca(NULL),
    dhfile(NULL),
    tls_dh(NULL),
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
    eecdhCurve(NULL)
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
    safe_free(clientca);
    safe_free(dhfile);
    safe_free(tls_dh);
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
    b->secure = secure;

#if USE_OPENSSL
    if (clientca)
        b->clientca = xstrdup(clientca);
    if (dhfile)
        b->dhfile = xstrdup(dhfile);
    if (tls_dh)
        b->tls_dh = xstrdup(tls_dh);
    if (sslContextSessionId)
        b->sslContextSessionId = xstrdup(sslContextSessionId);

#if 0
    // TODO: AYJ: 2015-01-15: for now SSL does not clone the context object.
    // cloning should only be done before the PortCfg is post-configure initialized and opened
    Security::ContextPointer sslContext;
#endif

#endif /*0*/

    return b;
}

#if USE_OPENSSL
void
AnyP::PortCfg::configureSslServerContext()
{
    if (!secure.certFile.isEmpty())
        Ssl::readCertChainAndPrivateKeyFromFiles(signingCert, signPkey, certsToChain, secure.certFile.c_str(), secure.privateKeyFile.c_str());

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

    if (!secure.crlFile.isEmpty())
        clientVerifyCrls.reset(Ssl::loadCrl(secure.crlFile.c_str(), secure.parsedFlags));

    if (clientca) {
        clientCA.reset(SSL_load_client_CA_file(clientca));
        if (clientCA.get() == NULL) {
            fatalf("Unable to read client CAs! from %s", clientca);
        }
    }

    secure.updateTlsVersionLimits();

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

    staticSslContext.reset(sslCreateServerContext(*this));

    if (!staticSslContext) {
        char buf[128];
        fatalf("%s_port %s initialization error", AnyP::ProtocolType_str[transport.protocol],  s.toUrl(buf, sizeof(buf)));
    }
}
#endif

