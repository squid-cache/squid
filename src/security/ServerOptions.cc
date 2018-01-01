/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/Packable.h"
#include "cache_cf.h"
#include "fatal.h"
#include "globals.h"
#include "security/ServerOptions.h"
#include "security/Session.h"
#include "SquidConfig.h"
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
        else
#endif
            clientCaStack = nullptr;

        staticContextSessionId = old.staticContextSessionId;
        generateHostCertificates = old.generateHostCertificates;
        signingCert = old.signingCert;
        signPkey = old.signPkey;
        certsToChain = old.certsToChain;
        untrustedSigningCert = old.untrustedSigningCert;
        untrustedSignPkey = old.untrustedSignPkey;
        dynamicCertMemCacheSize = old.dynamicCertMemCacheSize;
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

    } else if (strncmp(token, "dynamic_cert_mem_cache_size=", 28) == 0) {
        parseBytesOptionValue(&dynamicCertMemCacheSize, "bytes", token + 28);
        // XXX: parseBytesOptionValue() self_destruct()s on invalid values,
        // probably making this comparison and misleading ERROR unnecessary.
        if (dynamicCertMemCacheSize == std::numeric_limits<size_t>::max()) {
            debugs(3, DBG_CRITICAL, "ERROR: Cannot allocate memory for '" << token << "'. Using default of 4MB instead.");
            dynamicCertMemCacheSize = 4*1024*1024; // 4 MB
        }

    } else if (strcmp(token, "generate-host-certificates") == 0) {
        generateHostCertificates = true;
    } else if (strcmp(token, "generate-host-certificates=on") == 0) {
        generateHostCertificates = true;
    } else if (strcmp(token, "generate-host-certificates=off") == 0) {
        generateHostCertificates = false;

    } else if (strncmp(token, "context=", 8) == 0) {
#if USE_OPENSSL
        staticContextSessionId = SBuf(token+8);
        // to hide its arguably sensitive value, do not print token in these debugs
        if (staticContextSessionId.length() > SSL_MAX_SSL_SESSION_ID_LENGTH) {
            debugs(83, DBG_CRITICAL, "FATAL: Option 'context=' value is too long. Maximum " << SSL_MAX_SSL_SESSION_ID_LENGTH << " characters.");
            self_destruct();
        }
#else
        debugs(83, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Option 'context=' requires --with-openssl. Ignoring.");
#endif

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

    if (!generateHostCertificates)
        p->appendf(" %sgenerate-host-certificates=off", pfx);

    if (dynamicCertMemCacheSize != 4*1024*1024) // 4MB default, no 'tls-' prefix
        p->appendf(" dynamic_cert_mem_cache_size=%" PRIuSIZE "bytes", dynamicCertMemCacheSize);

    if (!staticContextSessionId.isEmpty())
        p->appendf(" %scontext=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(staticContextSessionId));
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
Security::ServerOptions::createSigningContexts(AnyP::PortCfg &port)
{
    const char *portType = AnyP::ProtocolType_str[port.transport.protocol];
    if (!certs.empty()) {
#if USE_OPENSSL
        Security::KeyData &keys = certs.front();
        Ssl::readCertChainAndPrivateKeyFromFiles(signingCert, signPkey, certsToChain, keys.certFile.c_str(), keys.privateKeyFile.c_str());
#else
        char buf[128];
        fatalf("Directive '%s_port %s' requires --with-openssl.", portType, port.s.toUrl(buf, sizeof(buf)));
#endif
    }

    if (!signingCert) {
        char buf[128];
        fatalf("No valid signing SSL certificate configured for %s_port %s", portType, port.s.toUrl(buf, sizeof(buf)));
    }

    if (!signPkey)
        debugs(3, DBG_IMPORTANT, "No SSL private key configured for  " << portType << "_port " << port.s);

#if USE_OPENSSL
    Ssl::generateUntrustedCert(untrustedSigningCert, untrustedSignPkey, signingCert, signPkey);
#endif

    if (!untrustedSigningCert) {
        char buf[128];
        fatalf("Unable to generate signing SSL certificate for untrusted sites for %s_port %s", portType, port.s.toUrl(buf, sizeof(buf)));
    }

    if (!createStaticServerContext(port)) {
        char buf[128];
        fatalf("%s_port %s initialization error", portType, port.s.toUrl(buf, sizeof(buf)));
    }
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

bool
Security::ServerOptions::updateContextConfig(Security::ContextPointer &ctx)
{
    updateContextOptions(ctx);
    updateContextSessionId(ctx);

#if USE_OPENSSL
    if (parsedFlags & SSL_FLAG_NO_SESSION_REUSE) {
        SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    }

    if (Config.SSL.unclean_shutdown) {
        debugs(83, 5, "Enabling quiet SSL shutdowns (RFC violation).");
        SSL_CTX_set_quiet_shutdown(ctx.get(), 1);
    }

    if (!sslCipher.isEmpty()) {
        debugs(83, 5, "Using cipher suite " << sslCipher << ".");
        if (!SSL_CTX_set_cipher_list(ctx.get(), sslCipher.c_str())) {
            auto ssl_error = ERR_get_error();
            debugs(83, DBG_CRITICAL, "ERROR: Failed to set SSL cipher suite '" << sslCipher << "': " <<  Security::ErrorString(ssl_error));
            return false;
        }
    }

    Ssl::MaybeSetupRsaCallback(ctx);
#endif

    updateContextEecdh(ctx);
    updateContextCa(ctx);
    updateContextClientCa(ctx);

#if USE_OPENSSL
    if (parsedFlags & SSL_FLAG_DONT_VERIFY_DOMAIN)
        SSL_CTX_set_ex_data(ctx.get(), ssl_ctx_ex_index_dont_verify_domain, (void *) -1);

    Security::SetSessionCacheCallbacks(ctx);
#endif
    return true;
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

void
Security::ServerOptions::updateContextSessionId(Security::ContextPointer &ctx)
{
#if USE_OPENSSL
    if (!staticContextSessionId.isEmpty())
        SSL_CTX_set_session_id_context(ctx.get(), reinterpret_cast<const unsigned char*>(staticContextSessionId.rawContent()), staticContextSessionId.length());
#endif
}

