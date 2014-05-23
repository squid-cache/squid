#include "squid.h"
#include "anyp/PortCfg.h"
#include "comm.h"
#include "fatal.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <cstring>
#include <limits>

CBDATA_NAMESPACED_CLASS_INIT(AnyP, PortCfg);

int NHttpSockets = 0;
int HttpSockets[MAXTCPLISTENPORTS];

AnyP::PortCfg::PortCfg() :
        next(NULL),
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
        vport(0),
        disable_pmtu_discovery(0),
        listenConn(),
#if USE_OPENSSL
        cert(NULL),
        key(NULL),
        version(0),
        cipher(NULL),
        options(NULL),
        clientca(NULL),
        cafile(NULL),
        capath(NULL),
        crlfile(NULL),
        dhfile(NULL),
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
        contextMethod(),
        sslContextFlags(0),
        sslOptions(0),
#endif
        ftp_track_dirs(false)
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
    safe_free(options);
    safe_free(cipher);
    safe_free(cafile);
    safe_free(capath);
    safe_free(dhfile);
    safe_free(sslflags);
    safe_free(sslContextSessionId);
#endif
}

AnyP::PortCfg *
AnyP::PortCfg::clone() const
{
    AnyP::PortCfg *b = new AnyP::PortCfg();
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
    b->disable_pmtu_discovery = disable_pmtu_discovery;
    b->tcp_keepalive = tcp_keepalive;
    b->ftp_track_dirs = ftp_track_dirs;

#if 0
    // TODO: AYJ: 2009-07-18: for now SSL does not clone. Configure separate ports with IPs and SSL settings

#if USE_OPENSSL
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
    char *sslContextSessionId;
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

    if (dhfile)
        dhParams.reset(Ssl::readDHParams(dhfile));

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

void
AnyP::PortCfg::setTransport(const char *aProtocol)
{
    // HTTP/1.0 not supported because we are version 1.1 which contains a superset of 1.0
    // and RFC 2616 requires us to upgrade 1.0 to 1.1

    if (strcasecmp("http", aProtocol) == 0 || strcmp("HTTP/1.1", aProtocol) == 0)
        transport = AnyP::ProtocolVersion(AnyP::PROTO_HTTP, 1,1);

    else if (strcasecmp("https", aProtocol) == 0 || strcmp("HTTPS/1.1", aProtocol) == 0)
        transport = AnyP::ProtocolVersion(AnyP::PROTO_HTTPS, 1,1);

    else if (strcasecmp("ftp", aProtocol) == 0)
        transport = AnyP::ProtocolVersion(AnyP::PROTO_FTP, 1,0);

    else
        fatalf("http(s)_port protocol=%s is not supported\n", aProtocol);
}
