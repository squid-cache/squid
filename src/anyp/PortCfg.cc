#include "squid.h"
#include "anyp/PortCfg.h"
#include "comm.h"
#if HAVE_LIMITS
#include <limits>
#endif

CBDATA_NAMESPACED_CLASS_INIT(AnyP, PortCfg);

int NHttpSockets = 0;
int HttpSockets[MAXTCPLISTENPORTS];

AnyP::PortCfg::PortCfg(const char *aProtocol)
#if USE_SSL
        :
        dynamicCertMemCacheSize(std::numeric_limits<size_t>::max())
#endif
{
    protocol = xstrdup(aProtocol);
}

AnyP::PortCfg::~PortCfg()
{
    if (Comm::IsConnOpen(listenConn)) {
        listenConn->close();
        listenConn = NULL;
    }

    safe_free(name);
    safe_free(defaultsite);
    safe_free(protocol);

#if USE_SSL
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
    AnyP::PortCfg *b = new AnyP::PortCfg(protocol);

    b->s = s;
    if (name)
        b->name = xstrdup(name);
    if (defaultsite)
        b->defaultsite = xstrdup(defaultsite);

    b->intercepted = intercepted;
    b->spoof_client_ip = spoof_client_ip;
    b->accel = accel;
    b->allow_direct = allow_direct;
    b->vhost = vhost;
    b->sslBump = sslBump;
    b->vport = vport;
    b->connection_auth_disabled = connection_auth_disabled;
    b->disable_pmtu_discovery = disable_pmtu_discovery;

    memcpy( &(b->tcp_keepalive), &(tcp_keepalive), sizeof(tcp_keepalive));

#if 0
    // AYJ: 2009-07-18: for now SSL does not clone. Configure separate ports with IPs and SSL settings

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
    char *sslContextSessionId;
    SSL_CTX *sslContext;
#endif

#endif /*0*/

    return b;
}
