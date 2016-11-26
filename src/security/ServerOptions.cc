/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Packable.h"
#include "globals.h"
#include "security/ServerOptions.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

#if HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#if HAVE_OPENSSL_X509_H
#include <openssl/x509.h>
#endif

void
Security::ServerOptions::parse(const char *token)
{
    if (!*token) {
        // config says just "ssl" or "tls" (or "tls-")
        encryptTransport = true;
        return;
    }

    // parse the server-only options
    if (strncmp(token, "dh=", 3) == 0) {
        // clear any previous Diffi-Helman configuration
        dh.clear();
        dhParamsFile.clear();
        eecdhCurve.clear();

        dh.append(token + 3);

        if (!dh.isEmpty()) {
            auto pos = dh.find(':');
            if (pos != SBuf::npos) {  // tls-dh=eecdhCurve:dhParamsFile
                eecdhCurve = dh.substr(0,pos);
                dhParamsFile = dh.substr(pos+1);
            } else {  // tls-dh=dhParamsFile
                dhParamsFile = dh;
                // empty eecdhCurve means "do not use EECDH"
            }
        }

        loadDhParams();

    } else if (strncmp(token, "dhparams=", 9) == 0) {
        if (!eecdhCurve.isEmpty()) {
            debugs(83, DBG_PARSE_NOTE(1), "UPGRADE WARNING: EECDH settings in tls-dh= override dhparams=");
            return;
        }

        // backward compatibility for dhparams= configuration
        dh.clear();
        dh.append(token + 9);
        dhParamsFile = dh;

        loadDhParams();

    } else {
        // parse generic TLS options
        Security::PeerOptions::parse(token);
    }
}

void
Security::ServerOptions::dumpCfg(Packable *p, const char *pfx) const
{
    // dump out the generic TLS options
    Security::PeerOptions::dumpCfg(p, pfx);

    if (!encryptTransport)
        return; // no other settings are relevant

    // dump the server-only options
    if (!dh.isEmpty())
        p->appendf(" %sdh=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(dh));
}

Security::ContextPointer
Security::ServerOptions::createBlankContext() const
{
    Security::ContextPointer ctx;
#if USE_OPENSSL
    Ssl::Initialize();

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    SSL_CTX *t = SSL_CTX_new(TLS_server_method());
#else
    SSL_CTX *t = SSL_CTX_new(SSLv23_server_method());
#endif
    if (!t) {
        const auto x = ERR_get_error();
        debugs(83, DBG_CRITICAL, "ERROR: Failed to allocate TLS server context: " << Security::ErrorString(x));
    }
    ctx.resetWithoutLocking(t);

#elif USE_GNUTLS
    // Initialize for X.509 certificate exchange
    gnutls_certificate_credentials_t t;
    if (const int x = gnutls_certificate_allocate_credentials(&t)) {
        debugs(83, DBG_CRITICAL, "ERROR: Failed to allocate TLS server context: " << Security::ErrorString(x));
    }
    ctx.resetWithoutLocking(t);

#else
    debugs(83, DBG_CRITICAL, "ERROR: Failed to allocate TLS server context: No TLS library");

#endif

    return ctx;
}

bool
Security::ServerOptions::createStaticServerContext(AnyP::PortCfg &port)
{
    updateTlsVersionLimits();

    Security::ContextPointer t(createBlankContext());
    if (t) {
#if USE_OPENSSL
        if (!Ssl::InitServerContext(t, port))
            return false;
#endif
    }

    staticContext = std::move(t);
    return bool(staticContext);
}

void
Security::ServerOptions::loadDhParams()
{
    if (dhParamsFile.isEmpty())
        return;

#if USE_OPENSSL
    DH *dhp = nullptr;
    if (FILE *in = fopen(dhParamsFile.c_str(), "r")) {
        dhp = PEM_read_DHparams(in, NULL, NULL, NULL);
        fclose(in);
    }

    if (!dhp) {
        debugs(83, DBG_IMPORTANT, "WARNING: Failed to read DH parameters '" << dhParamsFile << "'");
        return;
    }

    int codes;
    if (DH_check(dhp, &codes) == 0) {
        if (codes) {
            debugs(83, DBG_IMPORTANT, "WARNING: Failed to verify DH parameters '" << dhParamsFile << "' (" << std::hex << codes << ")");
            DH_free(dhp);
            dhp = nullptr;
        }
    }

    parsedDhParams.resetWithoutLocking(dhp);
#endif
}

void
Security::ServerOptions::updateContextEecdh(Security::ContextPointer &ctx)
{
    // set Elliptic Curve details into the server context
    if (!eecdhCurve.isEmpty()) {
        debugs(83, 9, "Setting Ephemeral ECDH curve to " << eecdhCurve << ".");

#if USE_OPENSSL && OPENSSL_VERSION_NUMBER >= 0x0090800fL && !defined(OPENSSL_NO_ECDH)
        int nid = OBJ_sn2nid(eecdhCurve.c_str());
        if (!nid) {
            debugs(83, DBG_CRITICAL, "ERROR: Unknown EECDH curve '" << eecdhCurve << "'");
            return;
        }

        auto ecdh = EC_KEY_new_by_curve_name(nid);
        if (!ecdh) {
            const auto x = ERR_get_error();
            debugs(83, DBG_CRITICAL, "ERROR: Unable to configure Ephemeral ECDH: " << Security::ErrorString(x));
            return;
        }

        if (!SSL_CTX_set_tmp_ecdh(ctx.get(), ecdh)) {
            const auto x = ERR_get_error();
            debugs(83, DBG_CRITICAL, "ERROR: Unable to set Ephemeral ECDH: " << Security::ErrorString(x));
        }
        EC_KEY_free(ecdh);

#else
        debugs(83, DBG_CRITICAL, "ERROR: EECDH is not available in this build." <<
               " Please link against OpenSSL>=0.9.8 and ensure OPENSSL_NO_ECDH is not set.");
#endif
    }

    // set DH parameters into the server context
#if USE_OPENSSL
    if (parsedDhParams) {
        SSL_CTX_set_tmp_dh(ctx.get(), parsedDhParams.get());
    }
#endif
}

