#include "squid.h"
#include "comm.h"
#include "ProtoPort.h"
#if HAVE_LIMITS
#include <limits>
#endif
#if USE_SSL
#include "ssl/support.h"
#endif

http_port_list::http_port_list(const char *aProtocol)
#if USE_SSL
        :
        dynamicCertMemCacheSize(std::numeric_limits<size_t>::max())
#endif
{
    protocol = xstrdup(aProtocol);
}

http_port_list::~http_port_list()
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

#if USE_SSL
void http_port_list::configureSslServerContext()
{
    staticSslContext.reset(
        sslCreateServerContext(cert, key,
                               version, cipher, options, sslflags, clientca,
                               cafile, capath, crlfile, dhfile,
                               sslContextSessionId));

    if (!staticSslContext) {
        char buf[128];
        fatalf("%s_port %s initialization error", protocol,  s.ToURL(buf, sizeof(buf)));
    }

    if (!sslBump)
        return;

    if (cert)
        Ssl::readCertChainAndPrivateKeyFromFiles(signingCert, signPkey, certsToChain, cert, key);

    if (!signingCert) {
        char buf[128];
        fatalf("No valid signing SSL certificate configured for %s_port %s", protocol,  s.ToURL(buf, sizeof(buf)));
    }

    if (!signPkey)
        debugs(3, DBG_IMPORTANT, "No SSL private key configured for  " <<  protocol << "_port " << s);

    Ssl::generateUntrustedCert(untrustedSigningCert, untrustedSignPkey,
                               signingCert, signPkey);

    if (!untrustedSigningCert) {
        char buf[128];
        fatalf("Unable to generate  signing SSL certificate for untrusted sites for %s_port %s", protocol, s.ToURL(buf, sizeof(buf)));
    }
}
#endif
