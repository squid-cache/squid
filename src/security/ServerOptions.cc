/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

Security::ServerOptions &
Security::ServerOptions::operator =(const Security::ServerOptions &old) {
    if (this != &old) {
        Security::PeerOptions::operator =(old);
        clientCaFile = old.clientCaFile;
        dh = old.dh;
        dhParamsFile = old.dhParamsFile;
        eecdhCurve = old.eecdhCurve;
        parsedDhParams = old.parsedDhParams;
#if USE_OPENSSL
        if (auto *stk = SSL_dup_CA_list(old.clientCaStack.get()))
            clientCaStack = Security::ServerOptions::X509_NAME_STACK_Pointer(stk);
#else
        clientCaStack = nullptr;
#endif
    }
    return *this;
}

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

#if HAVE_OPENSSL_SERVER_METHOD
    SSL_CTX *t = SSL_CTX_new(TLS_server_method());
#else
    SSL_CTX *t = SSL_CTX_new(SSLv23_server_method());
#endif
    if (!t) {
        const auto x = ERR_get_error();
        debugs(83, DBG_CRITICAL, "ERROR: Failed to allocate TLS server context: " << Security::ErrorString(x));
    }
    ctx = convertContextFromRawPtr(t);

#elif USE_GNUTLS
    // Initialize for X.509 certificate exchange
    gnutls_certificate_credentials_t t;
    if (const int x = gnutls_certificate_allocate_credentials(&t)) {
        debugs(83, DBG_CRITICAL, "ERROR: Failed to allocate TLS server context: " << Security::ErrorString(x));
    }
    ctx = convertContextFromRawPtr(t);

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
        if (!loadClientCaFile())
            return false;
    }

    staticContext = std::move(t);
    return bool(staticContext);
}

void
Security::ServerOptions::syncCaFiles()
{
    // if caFiles is set, just use that
    if (caFiles.size())
        return;

    // otherwise fall back to clientca if it is defined
    if (!clientCaFile.isEmpty())
        caFiles.emplace_back(clientCaFile);
}

/// load clientca= file (if any) into memory.
/// \retval true   clientca is not set, or loaded successfully
/// \retval false  unable to load the file, or not using OpenSSL
bool
Security::ServerOptions::loadClientCaFile()
{
    if (clientCaFile.isEmpty())
        return true;

#if USE_OPENSSL
    auto *stk = SSL_load_client_CA_file(clientCaFile.c_str());
    clientCaStack = Security::ServerOptions::X509_NAME_STACK_Pointer(stk);
#endif
    if (!clientCaStack) {
        debugs(83, DBG_CRITICAL, "FATAL: Unable to read client CAs from file: " << clientCaFile);
    }

    return bool(clientCaStack);
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
Security::ServerOptions::updateContextClientCa(Security::ContextPointer &ctx)
{
#if USE_OPENSSL
    if (clientCaStack) {
        ERR_clear_error();
        if (STACK_OF(X509_NAME) *clientca = SSL_dup_CA_list(clientCaStack.get())) {
            SSL_CTX_set_client_CA_list(ctx.get(), clientca);
        } else {
            auto ssl_error = ERR_get_error();
            debugs(83, DBG_CRITICAL, "ERROR: Failed to dupe the client CA list: " << Security::ErrorString(ssl_error));
            return;
        }

        if (parsedFlags & SSL_FLAG_DELAYED_AUTH) {
            debugs(83, 9, "Not requesting client certificates until acl processing requires one");
            SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
        } else {
            debugs(83, 9, "Requiring client certificates.");
            Ssl::SetupVerifyCallback(ctx);
        }

        updateContextCrl(ctx);

    } else {
        debugs(83, 9, "Not requiring any client certificates");
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);
    }
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

