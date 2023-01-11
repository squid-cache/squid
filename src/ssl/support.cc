/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL accelerator support */

#include "squid.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the SSL code from compile process when not needed.
 */
#if USE_OPENSSL

#include "acl/FilledChecklist.h"
#include "anyp/PortCfg.h"
#include "anyp/Uri.h"
#include "fatal.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "ipc/MemMap.h"
#include "security/CertError.h"
#include "security/ErrorDetail.h"
#include "security/Session.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "ssl/bio.h"
#include "ssl/Config.h"
#include "ssl/ErrorDetail.h"
#include "ssl/gadgets.h"
#include "ssl/support.h"

#include <cerrno>

// TODO: Move ssl_ex_index_* global variables from global.cc here.
static int ssl_ex_index_verify_callback_parameters = -1;

static Ssl::CertsIndexedList SquidUntrustedCerts;

const EVP_MD *Ssl::DefaultSignHash = NULL;

std::vector<const char *> Ssl::BumpModeStr = {
    "none",
    "client-first",
    "server-first",
    "peek",
    "stare",
    "bump",
    "splice",
    "terminate"
    /*,"err"*/
};

/**
 \defgroup ServerProtocolSSLInternal Server-Side SSL Internals
 \ingroup ServerProtocolSSLAPI
 */

int
Ssl::AskPasswordCb(char *buf, int size, int rwflag, void *userdata)
{
    FILE *in;
    int len = 0;
    char cmdline[1024];

    snprintf(cmdline, sizeof(cmdline), "\"%s\" \"%s\"", ::Config.Program.ssl_password, (const char *)userdata);
    in = popen(cmdline, "r");

    if (fgets(buf, size, in))

        len = strlen(buf);

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        --len;

    buf[len] = '\0';

    pclose(in);

    return len;
}

/// \ingroup ServerProtocolSSLInternal
static void
ssl_ask_password(SSL_CTX * context, const char * prompt)
{
    if (Config.Program.ssl_password) {
        SSL_CTX_set_default_passwd_cb(context, Ssl::AskPasswordCb);
        SSL_CTX_set_default_passwd_cb_userdata(context, (void *)prompt);
    }
}

#if HAVE_LIBSSL_SSL_CTX_SET_TMP_RSA_CALLBACK
static RSA *
ssl_temp_rsa_cb(SSL * ssl, int anInt, int keylen)
{
    static RSA *rsa_512 = nullptr;
    static RSA *rsa_1024 = nullptr;
    static BIGNUM *e = nullptr;
    RSA *rsa = nullptr;
    int newkey = 0;

    if (!e) {
        e = BN_new();
        if (!e || !BN_set_word(e, RSA_F4)) {
            debugs(83, DBG_IMPORTANT, "ssl_temp_rsa_cb: Failed to set exponent for key " << keylen);
            BN_free(e);
            e = nullptr;
            return nullptr;
        }
    }

    switch (keylen) {

    case 512:

        if (!rsa_512) {
            rsa_512 = RSA_new();
            if (rsa_512 && RSA_generate_key_ex(rsa_512, 512, e, nullptr)) {
                newkey = 1;
            } else {
                RSA_free(rsa_512);
                rsa_512 = nullptr;
            }
        }

        rsa = rsa_512;
        break;

    case 1024:

        if (!rsa_1024) {
            rsa_1024 = RSA_new();
            if (rsa_1024 && RSA_generate_key_ex(rsa_1024, 1024, e, nullptr)) {
                newkey = 1;
            } else {
                RSA_free(rsa_1024);
                rsa_1024 = nullptr;
            }
        }

        rsa = rsa_1024;
        break;

    default:
        debugs(83, DBG_IMPORTANT, "ssl_temp_rsa_cb: Unexpected key length " << keylen);
        return NULL;
    }

    if (rsa == NULL) {
        debugs(83, DBG_IMPORTANT, "ssl_temp_rsa_cb: Failed to generate key " << keylen);
        return NULL;
    }

    if (newkey) {
        if (Debug::Enabled(83, 5))
            PEM_write_RSAPrivateKey(debug_log, rsa, NULL, NULL, 0, NULL, NULL);

        debugs(83, DBG_IMPORTANT, "Generated ephemeral RSA key of length " << keylen);
    }

    return rsa;
}
#endif

void
Ssl::MaybeSetupRsaCallback(Security::ContextPointer &ctx)
{
#if HAVE_LIBSSL_SSL_CTX_SET_TMP_RSA_CALLBACK
    debugs(83, 9, "Setting RSA key generation callback.");
    SSL_CTX_set_tmp_rsa_callback(ctx.get(), ssl_temp_rsa_cb);
#endif
}

int Ssl::asn1timeToString(ASN1_TIME *tm, char *buf, int len)
{
    BIO *bio;
    int write = 0;
    bio = BIO_new(BIO_s_mem());
    if (bio) {
        if (ASN1_TIME_print(bio, tm))
            write = BIO_read(bio, buf, len-1);
        BIO_free(bio);
    }
    buf[write]='\0';
    return write;
}

int Ssl::matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data))
{
    assert(peer_cert);

    X509_NAME *name = X509_get_subject_name(peer_cert);

    for (int i = X509_NAME_get_index_by_NID(name, NID_commonName, -1); i >= 0; i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) {

        ASN1_STRING *cn_data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

        if ( (*check_func)(check_data, cn_data) == 0)
            return 1;
    }

    STACK_OF(GENERAL_NAME) * altnames;
    altnames = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(peer_cert, NID_subject_alt_name, NULL, NULL);

    if (altnames) {
        int numalts = sk_GENERAL_NAME_num(altnames);
        for (int i = 0; i < numalts; ++i) {
            const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);
            if (check->type != GEN_DNS) {
                continue;
            }
            ASN1_STRING *cn_data = check->d.dNSName;

            if ( (*check_func)(check_data, cn_data) == 0) {
                sk_GENERAL_NAME_pop_free(altnames, GENERAL_NAME_free);
                return 1;
            }
        }
        sk_GENERAL_NAME_pop_free(altnames, GENERAL_NAME_free);
    }
    return 0;
}

static int check_domain( void *check_data, ASN1_STRING *cn_data)
{
    char cn[1024];
    const char *server = (const char *)check_data;

    if (cn_data->length == 0)
        return 1; // zero length cn, ignore

    if (cn_data->length > (int)sizeof(cn) - 1)
        return 1; //if does not fit our buffer just ignore

    char *s = reinterpret_cast<char*>(cn_data->data);
    char *d = cn;
    for (int i = 0; i < cn_data->length; ++i, ++d, ++s) {
        if (*s == '\0')
            return 1; // always a domain mismatch. contains 0x00
        *d = *s;
    }
    cn[cn_data->length] = '\0';
    debugs(83, 4, "Verifying server domain " << server << " to certificate name/subjectAltName " << cn);
    return matchDomainName(server, (cn[0] == '*' ? cn + 1 : cn), mdnRejectSubsubDomains);
}

bool Ssl::checkX509ServerValidity(X509 *cert, const char *server)
{
    return matchX509CommonNames(cert, (void *)server, check_domain);
}

/// adjusts OpenSSL validation results for each verified certificate in ctx
/// OpenSSL "verify_callback function" (\ref OpenSSL_vcb_disambiguation)
static int
ssl_verify_cb(int ok, X509_STORE_CTX * ctx)
{
    // preserve original ctx->error before SSL_ calls can overwrite it
    Security::ErrorCode error_no = ok ? SSL_ERROR_NONE : X509_STORE_CTX_get_error(ctx);

    char buffer[256] = "";
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    SSL_CTX *sslctx = SSL_get_SSL_CTX(ssl);
    SBuf *server = (SBuf *)SSL_get_ex_data(ssl, ssl_ex_index_server);
    void *dont_verify_domain = SSL_CTX_get_ex_data(sslctx, ssl_ctx_ex_index_dont_verify_domain);
    ACLChecklist *check = (ACLChecklist*)SSL_get_ex_data(ssl, ssl_ex_index_cert_error_check);
    X509 *peeked_cert = (X509 *)SSL_get_ex_data(ssl, ssl_ex_index_ssl_peeked_cert);
    Security::CertPointer peer_cert;
    peer_cert.resetAndLock(X509_STORE_CTX_get0_cert(ctx));

    X509_NAME_oneline(X509_get_subject_name(peer_cert.get()), buffer, sizeof(buffer));

    // detect infinite loops
    uint32_t *validationCounter = static_cast<uint32_t *>(SSL_get_ex_data(ssl, ssl_ex_index_ssl_validation_counter));
    if (!validationCounter) {
        validationCounter = new uint32_t(1);
        SSL_set_ex_data(ssl, ssl_ex_index_ssl_validation_counter, validationCounter);
    } else {
        // overflows allowed if SQUID_CERT_VALIDATION_ITERATION_MAX >= UINT32_MAX
        (*validationCounter)++;
    }

    if ((*validationCounter) >= SQUID_CERT_VALIDATION_ITERATION_MAX) {
        ok = 0; // or the validation loop will never stop
        error_no = SQUID_X509_V_ERR_INFINITE_VALIDATION;
        debugs(83, 2, "SQUID_X509_V_ERR_INFINITE_VALIDATION: " <<
               *validationCounter << " iterations while checking " << buffer);
    }

    if (ok) {
        debugs(83, 5, "SSL Certificate signature OK: " << buffer);

        // Check for domain mismatch only if the current certificate is the peer certificate.
        if (!dont_verify_domain && server && peer_cert.get() == X509_STORE_CTX_get_current_cert(ctx)) {
            if (!Ssl::checkX509ServerValidity(peer_cert.get(), server->c_str())) {
                debugs(83, 2, "SQUID_X509_V_ERR_DOMAIN_MISMATCH: Certificate " << buffer << " does not match domainname " << server);
                ok = 0;
                error_no = SQUID_X509_V_ERR_DOMAIN_MISMATCH;
            }
        }
    }

    if (ok && peeked_cert) {
        // Check whether the already peeked certificate matches the new one.
        if (X509_cmp(peer_cert.get(), peeked_cert) != 0) {
            debugs(83, 2, "SQUID_X509_V_ERR_CERT_CHANGE: Certificate " << buffer << " does not match peeked certificate");
            ok = 0;
            error_no =  SQUID_X509_V_ERR_CERT_CHANGE;
        }
    }

    if (!ok && error_no == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
        if (const auto params = Ssl::VerifyCallbackParameters::Find(*ssl)) {
            if (params->callerHandlesMissingCertificates) {
                debugs(83, 3, "hiding X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
                params->hidMissingIssuer = true;
                ok = 1;
            }
        }
    }

    if (!ok) {
        Security::CertPointer broken_cert;
        broken_cert.resetAndLock(X509_STORE_CTX_get_current_cert(ctx));
        if (!broken_cert)
            broken_cert = peer_cert;

        Security::CertErrors *errs = static_cast<Security::CertErrors *>(SSL_get_ex_data(ssl, ssl_ex_index_ssl_errors));
        const int depth = X509_STORE_CTX_get_error_depth(ctx);
        if (!errs) {
            errs = new Security::CertErrors(Security::CertError(error_no, broken_cert, depth));
            if (!SSL_set_ex_data(ssl, ssl_ex_index_ssl_errors,  (void *)errs)) {
                debugs(83, 2, "Failed to set ssl error_no in ssl_verify_cb: Certificate " << buffer);
                delete errs;
                errs = NULL;
            }
        } else // remember another error number
            errs->push_back_unique(Security::CertError(error_no, broken_cert, depth));

        if (const char *err_descr = Ssl::GetErrorDescr(error_no))
            debugs(83, 5, err_descr << ": " << buffer);
        else
            debugs(83, DBG_IMPORTANT, "SSL unknown certificate error " << error_no << " in " << buffer);

        // Check if the certificate error can be bypassed.
        // Infinity validation loop errors can not bypassed.
        if (error_no != SQUID_X509_V_ERR_INFINITE_VALIDATION) {
            if (check) {
                ACLFilledChecklist *filledCheck = Filled(check);
                assert(!filledCheck->sslErrors);
                filledCheck->sslErrors = new Security::CertErrors(Security::CertError(error_no, broken_cert));
                filledCheck->serverCert = peer_cert;
                if (check->fastCheck().allowed()) {
                    debugs(83, 3, "bypassing SSL error " << error_no << " in " << buffer);
                    ok = 1;
                } else {
                    debugs(83, 5, "confirming SSL error " << error_no);
                }
                delete filledCheck->sslErrors;
                filledCheck->sslErrors = NULL;
                filledCheck->serverCert.reset();
            }
            // If the certificate validator is used then we need to allow all errors and
            // pass them to certficate validator for more processing
            else if (Ssl::TheConfig.ssl_crt_validator) {
                ok = 1;
            }
        }
    }

    if (Ssl::TheConfig.ssl_crt_validator) {
        // Check if we have stored certificates chain. Store if not.
        if (!SSL_get_ex_data(ssl, ssl_ex_index_ssl_cert_chain)) {
            STACK_OF(X509) *certStack = X509_STORE_CTX_get1_chain(ctx);
            if (certStack && !SSL_set_ex_data(ssl, ssl_ex_index_ssl_cert_chain, certStack))
                sk_X509_pop_free(certStack, X509_free);
        }
    }

    if (!ok && !SSL_get_ex_data(ssl, ssl_ex_index_ssl_error_detail) ) {

        // Find the broken certificate. It may be intermediate.
        Security::CertPointer broken_cert(peer_cert); // reasonable default if search fails
        // Our SQUID_X509_V_ERR_DOMAIN_MISMATCH implies peer_cert is at fault.
        if (error_no != SQUID_X509_V_ERR_DOMAIN_MISMATCH) {
            if (auto *last_used_cert = X509_STORE_CTX_get_current_cert(ctx))
                broken_cert.resetAndLock(last_used_cert);
        }

        std::unique_ptr<Security::ErrorDetail::Pointer> edp(new Security::ErrorDetail::Pointer(
                    new Security::ErrorDetail(error_no, peer_cert, broken_cert)));
        if (SSL_set_ex_data(ssl, ssl_ex_index_ssl_error_detail, edp.get()))
            edp.release();
        else
            debugs(83, 2, "failed to store a " << buffer << " error detail: " << *edp);
    }

    return ok;
}

void
Ssl::ConfigurePeerVerification(Security::ContextPointer &ctx, const Security::ParsedPortFlags flags)
{
    int mode;

    // assume each flag is exclusive; flags creator must check this assumption
    if (flags & SSL_FLAG_DONT_VERIFY_PEER) {
        debugs(83, DBG_IMPORTANT, "SECURITY WARNING: Peer certificates are not verified for validity!");
        debugs(83, DBG_IMPORTANT, "UPGRADE NOTICE: The DONT_VERIFY_PEER flag is deprecated. Remove the clientca= option to disable client certificates.");
        mode = SSL_VERIFY_NONE;
    }
    else if (flags & SSL_FLAG_DELAYED_AUTH) {
        debugs(83, DBG_PARSE_NOTE(3), "not requesting client certificates until ACL processing requires one");
        mode = SSL_VERIFY_NONE;
    }
    else if (flags & SSL_FLAG_CONDITIONAL_AUTH) {
        debugs(83, DBG_PARSE_NOTE(3), "will request the client certificate but ignore its absence");
        mode = SSL_VERIFY_PEER;
    }
    else {
        debugs(83, DBG_PARSE_NOTE(3), "Requiring client certificates.");
        mode = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    SSL_CTX_set_verify(ctx.get(), mode, (mode != SSL_VERIFY_NONE) ? ssl_verify_cb : nullptr);
}

void
Ssl::DisablePeerVerification(Security::ContextPointer &ctx)
{
    debugs(83, DBG_PARSE_NOTE(3), "Not requiring any client certificates");
    SSL_CTX_set_verify(ctx.get(),SSL_VERIFY_NONE,nullptr);
}

static int VerifyCtxCertificates(X509_STORE_CTX *ctx, STACK_OF(X509) *extraCerts);

bool
Ssl::VerifyConnCertificates(Security::Connection &sconn, const Ssl::X509_STACK_Pointer &extraCerts)
{
    const auto peerCertificatesChain = SSL_get_peer_cert_chain(&sconn);

    // TODO: Replace debugs/return false with returning ErrorDetail::Pointer.
    // Using Security::ErrorDetail terminology, errors in _this_ function are
    // "non-validation errors", but VerifyCtxCertificates() errors may be
    // "certificate validation errors". Callers detail SQUID_TLS_ERR_CONNECT.
    // Some details should be created right here. Others extracted from OpenSSL.
    // Why not throw? Most of the reasons detailed in the following commit apply
    // here as well: https://github.com/measurement-factory/squid/commit/e862d33

    if (!peerCertificatesChain || sk_X509_num(peerCertificatesChain) == 0) {
        debugs(83, 2, "no server certificates");
        return false;
    }

    const auto verificationStore = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(&sconn));
    if (!verificationStore) {
        debugs(83, 2, "no certificate store");
        return false;
    }

    const X509_STORE_CTX_Pointer storeCtx(X509_STORE_CTX_new());
    if (!storeCtx) {
        debugs(83, 2, "cannot create X509_STORE_CTX; likely OOM");
        return false;
    }

    const auto peerCert = sk_X509_value(peerCertificatesChain, 0);
    if (!X509_STORE_CTX_init(storeCtx.get(), verificationStore, peerCert, peerCertificatesChain)) {
        debugs(83, 2, "cannot initialize X509_STORE_CTX");
        return false;
    }

#if defined(SSL_CERT_FLAG_SUITEB_128_LOS)
    // overwrite context Suite B (RFC 5759) flags with connection non-defaults
    // SSL_set_cert_flags() return type is long, but its implementation actually
    // returns an unsigned long flags value expected by X509_STORE_CTX_set_flags
    const unsigned long certFlags = SSL_set_cert_flags(&sconn, 0);
    if (const auto suiteBflags = certFlags & SSL_CERT_FLAG_SUITEB_128_LOS)
        X509_STORE_CTX_set_flags(storeCtx.get(), suiteBflags);
#endif

    if (!X509_STORE_CTX_set_ex_data(storeCtx.get(), SSL_get_ex_data_X509_STORE_CTX_idx(), &sconn)) {
        debugs(83, 2, "cannot attach SSL object to X509_STORE_CTX");
        return false;
    }

    // If we ever add DANE support to Squid, we will supply DANE details here:
    // X509_STORE_CTX_set0_dane(storeCtx.get(), SSL_get0_dane(&sconn));

    // tell OpenSSL we are verifying a server certificate
    if (!X509_STORE_CTX_set_default(storeCtx.get(), "ssl_server")) {
        debugs(83, 2, "cannot set default verification method to ssl_server");
        return false;
    }

    // overwrite context "verification parameters" with connection non-defaults
    const auto param = X509_STORE_CTX_get0_param(storeCtx.get());
    if (!param) {
        debugs(83, 2, "no context verification parameters");
        return false;
    }
#if defined(HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL)
    X509_VERIFY_PARAM_set_auth_level(param, SSL_get_security_level(&sconn));
#endif
    if (!X509_VERIFY_PARAM_set1(param, SSL_get0_param(&sconn))) {
        debugs(83, 2, "cannot overwrite context verification parameters");
        return false;
    }

    // copy any connection "verify_callback function" to the validation context
    // (\ref OpenSSL_vcb_disambiguation)
    if (const auto cb = SSL_get_verify_callback(&sconn))
        X509_STORE_CTX_set_verify_cb(storeCtx.get(), cb);

    // verify the server certificate chain in the prepared validation context
    if (VerifyCtxCertificates(storeCtx.get(), extraCerts.get()) <= 0) {
        // see also: ssl_verify_cb() details errors via ssl_ex_index_ssl_errors
        const auto verifyResult = X509_STORE_CTX_get_error(storeCtx.get());
        debugs(83, 3, "verification failure: " << verifyResult << ' ' << X509_verify_cert_error_string(verifyResult));
        return false;
    }

    debugs(83, 7, "success");
    return true;
}

/* Ssl::VerifyCallbackParameters */

Ssl::VerifyCallbackParameters *
Ssl::VerifyCallbackParameters::Find(Security::Connection &sconn)
{
    return static_cast<VerifyCallbackParameters*>(SSL_get_ex_data(&sconn, ssl_ex_index_verify_callback_parameters));
}

Ssl::VerifyCallbackParameters *
Ssl::VerifyCallbackParameters::New(Security::Connection &sconn)
{
    Must(!Find(sconn));
    const auto parameters = new VerifyCallbackParameters();
    if (!SSL_set_ex_data(&sconn, ssl_ex_index_verify_callback_parameters, parameters)) {
        delete parameters;
        throw TextException("SSL_set_ex_data() failed; likely OOM", Here());
    }
    return parameters;
}

Ssl::VerifyCallbackParameters &
Ssl::VerifyCallbackParameters::At(Security::Connection &sconn)
{
    const auto parameters = Find(sconn);
    Must(parameters);
    return *parameters;
}

// "dup" function for SSL_get_ex_new_index("cert_err_check")
#if OPENSSL_VERSION_MAJOR >= 3
static int
ssl_dupAclChecklist(CRYPTO_EX_DATA *, const CRYPTO_EX_DATA *, void **,
                    int, long, void *)
#elif SQUID_USE_CONST_CRYPTO_EX_DATA_DUP
static int
ssl_dupAclChecklist(CRYPTO_EX_DATA *, const CRYPTO_EX_DATA *, void *,
                    int, long, void *)
#else
static int
ssl_dupAclChecklist(CRYPTO_EX_DATA *, CRYPTO_EX_DATA *, void *,
                    int, long, void *)
#endif
{
    // We do not support duplication of ACLCheckLists.
    // If duplication is needed, we can count copies with cbdata.
    assert(false);
    return 0;
}

// "free" function for SSL_get_ex_new_index("cert_err_check")
static void
ssl_freeAclChecklist(void *, void *ptr, CRYPTO_EX_DATA *,
                     int, long, void *)
{
    delete static_cast<ACLChecklist *>(ptr); // may be NULL
}

// "free" function for SSL_get_ex_new_index("ssl_error_detail")
static void
ssl_free_ErrorDetail(void *, void *ptr, CRYPTO_EX_DATA *,
                     int, long, void *)
{
    const auto errDetail = static_cast<Security::ErrorDetail::Pointer*>(ptr);
    delete errDetail;
}

static void
ssl_free_SslErrors(void *, void *ptr, CRYPTO_EX_DATA *,
                   int, long, void *)
{
    Security::CertErrors *errs = static_cast <Security::CertErrors*>(ptr);
    delete errs;
}

// "free" function for SSL_get_ex_new_index("ssl_ex_index_ssl_validation_counter")
static void
ssl_free_int(void *, void *ptr, CRYPTO_EX_DATA *,
             int, long, void *)
{
    uint32_t *counter = static_cast <uint32_t *>(ptr);
    delete counter;
}

/// \ingroup ServerProtocolSSLInternal
/// Callback handler function to release STACK_OF(X509) "ex" data stored
/// in an SSL object.
static void
ssl_free_CertChain(void *, void *ptr, CRYPTO_EX_DATA *,
                   int, long, void *)
{
    STACK_OF(X509) *certsChain = static_cast <STACK_OF(X509) *>(ptr);
    sk_X509_pop_free(certsChain,X509_free);
}

// "free" function for X509 certificates
static void
ssl_free_X509(void *, void *ptr, CRYPTO_EX_DATA *,
              int, long, void *)
{
    X509  *cert = static_cast <X509 *>(ptr);
    X509_free(cert);
}

// "free" function for SBuf
static void
ssl_free_SBuf(void *, void *ptr, CRYPTO_EX_DATA *,
              int, long, void *)
{
    SBuf  *buf = static_cast <SBuf *>(ptr);
    delete buf;
}

/// "free" function for the ssl_ex_index_verify_callback_parameters entry
static void
ssl_free_VerifyCallbackParameters(void *, void *ptr, CRYPTO_EX_DATA *,
                                  int, long, void *)
{
    delete static_cast<Ssl::VerifyCallbackParameters*>(ptr);
}

void
Ssl::Initialize(void)
{
    static bool initialized = false;
    if (initialized)
        return;
    initialized = true;

    SQUID_OPENSSL_init_ssl();

    if (::Config.SSL.ssl_engine) {
#if OPENSSL_VERSION_MAJOR < 3
        debugs(83, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Support for ssl_engine is deprecated " <<
               "in Squids built with OpenSSL 1.x (like this Squid). " <<
               "It is removed in Squids built with OpenSSL 3.0 or newer.");
#if !defined(OPENSSL_NO_ENGINE)
        ENGINE_load_builtin_engines();
        ENGINE *e;
        if (!(e = ENGINE_by_id(::Config.SSL.ssl_engine)))
            fatalf("Unable to find SSL engine '%s'\n", ::Config.SSL.ssl_engine);

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            const auto ssl_error = ERR_get_error();
            fatalf("Failed to initialise SSL engine: %s\n", Security::ErrorString(ssl_error));
        }
#else /* OPENSSL_NO_ENGINE */
        throw TextException("Cannot use ssl_engine in Squid built with OpenSSL configured to disable SSL engine support", Here());
#endif

#else /* OPENSSL_VERSION_MAJOR */
        throw TextException("Cannot use ssl_engine in Squid built with OpenSSL 3.0 or newer", Here());
#endif
    }

    const char *defName = ::Config.SSL.certSignHash ? ::Config.SSL.certSignHash : SQUID_SSL_SIGN_HASH_IF_NONE;
    Ssl::DefaultSignHash = EVP_get_digestbyname(defName);
    if (!Ssl::DefaultSignHash)
        fatalf("Sign hash '%s' is not supported\n", defName);

    ssl_ex_index_server = SSL_get_ex_new_index(0, (void *) "server", NULL, NULL, ssl_free_SBuf);
    ssl_ctx_ex_index_dont_verify_domain = SSL_CTX_get_ex_new_index(0, (void *) "dont_verify_domain", NULL, NULL, NULL);
    ssl_ex_index_cert_error_check = SSL_get_ex_new_index(0, (void *) "cert_error_check", NULL, &ssl_dupAclChecklist, &ssl_freeAclChecklist);
    ssl_ex_index_ssl_error_detail = SSL_get_ex_new_index(0, (void *) "ssl_error_detail", NULL, NULL, &ssl_free_ErrorDetail);
    ssl_ex_index_ssl_peeked_cert  = SSL_get_ex_new_index(0, (void *) "ssl_peeked_cert", NULL, NULL, &ssl_free_X509);
    ssl_ex_index_ssl_errors =  SSL_get_ex_new_index(0, (void *) "ssl_errors", NULL, NULL, &ssl_free_SslErrors);
    ssl_ex_index_ssl_cert_chain = SSL_get_ex_new_index(0, (void *) "ssl_cert_chain", NULL, NULL, &ssl_free_CertChain);
    ssl_ex_index_ssl_validation_counter = SSL_get_ex_new_index(0, (void *) "ssl_validation_counter", NULL, NULL, &ssl_free_int);
    ssl_ex_index_verify_callback_parameters = SSL_get_ex_new_index(0, (void *) "verify_callback_parameters", nullptr, nullptr, &ssl_free_VerifyCallbackParameters);
}

bool
Ssl::InitServerContext(Security::ContextPointer &ctx, AnyP::PortCfg &port)
{
    if (!ctx)
        return false;

    return true;
}

bool
Ssl::InitClientContext(Security::ContextPointer &ctx, Security::PeerOptions &peer, Security::ParsedPortFlags fl)
{
    if (!ctx)
        return false;

    if (!peer.sslCipher.isEmpty()) {
        debugs(83, 5, "Using chiper suite " << peer.sslCipher << ".");

        const char *cipher = peer.sslCipher.c_str();
        if (!SSL_CTX_set_cipher_list(ctx.get(), cipher)) {
            const auto ssl_error = ERR_get_error();
            fatalf("Failed to set SSL cipher suite '%s': %s\n",
                   cipher, Security::ErrorString(ssl_error));
        }
    }

    if (!peer.certs.empty()) {
        // TODO: support loading multiple cert/key pairs
        auto &keys = peer.certs.front();
        if (!keys.certFile.isEmpty()) {
            debugs(83, DBG_IMPORTANT, "Using certificate in " << keys.certFile);

            const char *certfile = keys.certFile.c_str();
            if (!SSL_CTX_use_certificate_chain_file(ctx.get(), certfile)) {
                const auto ssl_error = ERR_get_error();
                fatalf("Failed to acquire SSL certificate '%s': %s\n",
                       certfile, Security::ErrorString(ssl_error));
            }

            debugs(83, DBG_IMPORTANT, "Using private key in " << keys.privateKeyFile);
            const char *keyfile = keys.privateKeyFile.c_str();
            ssl_ask_password(ctx.get(), keyfile);

            if (!SSL_CTX_use_PrivateKey_file(ctx.get(), keyfile, SSL_FILETYPE_PEM)) {
                const auto ssl_error = ERR_get_error();
                fatalf("Failed to acquire SSL private key '%s': %s\n",
                       keyfile, Security::ErrorString(ssl_error));
            }

            debugs(83, 5, "Comparing private and public SSL keys.");

            if (!SSL_CTX_check_private_key(ctx.get())) {
                const auto ssl_error = ERR_get_error();
                fatalf("SSL private key '%s' does not match public key '%s': %s\n",
                       certfile, keyfile, Security::ErrorString(ssl_error));
            }
        }
    }

    MaybeSetupRsaCallback(ctx);

    Ssl::ConfigurePeerVerification(ctx, fl);

    return true;
}

/// \ingroup ServerProtocolSSLInternal
static const char *
ssl_get_attribute(X509_NAME * name, const char *attribute_name)
{
    static char buffer[1024];
    buffer[0] = '\0';

    if (strcmp(attribute_name, "DN") == 0) {
        X509_NAME_oneline(name, buffer, sizeof(buffer));
    } else {
        int nid = OBJ_txt2nid(const_cast<char *>(attribute_name));
        if (nid == 0) {
            debugs(83, DBG_IMPORTANT, "WARNING: Unknown SSL attribute name '" << attribute_name << "'");
            return nullptr;
        }
        X509_NAME_get_text_by_NID(name, nid, buffer, sizeof(buffer));
    }

    return *buffer ? buffer : nullptr;
}

/// \ingroup ServerProtocolSSLInternal
const char *
Ssl::GetX509UserAttribute(X509 * cert, const char *attribute_name)
{
    X509_NAME *name;
    const char *ret;

    if (!cert)
        return NULL;

    name = X509_get_subject_name(cert);

    ret = ssl_get_attribute(name, attribute_name);

    return ret;
}

const char *
Ssl::GetX509Fingerprint(X509 * cert, const char *)
{
    static char buf[1024];
    if (!cert)
        return NULL;

    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];
    if (!X509_digest(cert, EVP_sha1(), md, &n))
        return NULL;

    assert(3 * n + 1 < sizeof(buf));

    char *s = buf;
    for (unsigned int i=0; i < n; ++i, s += 3) {
        const char term = (i + 1 < n) ? ':' : '\0';
        snprintf(s, 4, "%02X%c", md[i], term);
    }

    return buf;
}

SBuf
Ssl::GetX509PEM(X509 * cert)
{
    assert(cert);

    Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(bio.get(), cert);

    char *ptr;
    const auto len = BIO_get_mem_data(bio.get(), &ptr);
    return SBuf(ptr, len);
}

/// \ingroup ServerProtocolSSLInternal
const char *
Ssl::GetX509CAAttribute(X509 * cert, const char *attribute_name)
{

    X509_NAME *name;
    const char *ret;

    if (!cert)
        return NULL;

    name = X509_get_issuer_name(cert);

    ret = ssl_get_attribute(name, attribute_name);

    return ret;
}

const char *sslGetUserAttribute(SSL *ssl, const char *attribute_name)
{
    if (!ssl)
        return NULL;

    X509 *cert = SSL_get_peer_certificate(ssl);

    const char *attr = Ssl::GetX509UserAttribute(cert, attribute_name);

    X509_free(cert);
    return attr;
}

const char *sslGetCAAttribute(SSL *ssl, const char *attribute_name)
{
    if (!ssl)
        return NULL;

    X509 *cert = SSL_get_peer_certificate(ssl);

    const char *attr = Ssl::GetX509CAAttribute(cert, attribute_name);

    X509_free(cert);
    return attr;
}

const char *
sslGetUserEmail(SSL * ssl)
{
    return sslGetUserAttribute(ssl, "emailAddress");
}

SBuf
sslGetUserCertificatePEM(SSL *ssl)
{
    assert(ssl);

    if (const auto cert = SSL_get_peer_certificate(ssl))
        return Ssl::GetX509PEM(cert);

    return SBuf();
}

SBuf
sslGetUserCertificateChainPEM(SSL *ssl)
{
    assert(ssl);

    auto chain = SSL_get_peer_cert_chain(ssl);

    if (!chain)
        return sslGetUserCertificatePEM(ssl);

    Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));

    for (int i = 0; i < sk_X509_num(chain); ++i) {
        X509 *cert = sk_X509_value(chain, i);
        PEM_write_bio_X509(bio.get(), cert);
    }

    char *ptr;
    const auto len = BIO_get_mem_data(bio.get(), &ptr);
    return SBuf(ptr, len);
}

/// Create SSL context and apply ssl certificate and private key to it.
Security::ContextPointer
Ssl::createSSLContext(Security::CertPointer & x509, Security::PrivateKeyPointer & pkey, Security::ServerOptions &options)
{
    Security::ContextPointer ctx(options.createBlankContext());

    if (!SSL_CTX_use_certificate(ctx.get(), x509.get()))
        return Security::ContextPointer();

    if (!SSL_CTX_use_PrivateKey(ctx.get(), pkey.get()))
        return Security::ContextPointer();

    if (!options.updateContextConfig(ctx))
        return Security::ContextPointer();

    return ctx;
}

Security::ContextPointer
Ssl::GenerateSslContextUsingPkeyAndCertFromMemory(const char * data, Security::ServerOptions &options, bool trusted)
{
    Security::CertPointer cert;
    Security::PrivateKeyPointer pkey;
    if (!readCertAndPrivateKeyFromMemory(cert, pkey, data) || !cert || !pkey)
        return Security::ContextPointer();

    Security::ContextPointer ctx(createSSLContext(cert, pkey, options));
    if (ctx && trusted)
        Ssl::chainCertificatesToSSLContext(ctx, options);
    return ctx;
}

Security::ContextPointer
Ssl::GenerateSslContext(CertificateProperties const &properties, Security::ServerOptions &options, bool trusted)
{
    Security::CertPointer cert;
    Security::PrivateKeyPointer pkey;
    if (!generateSslCertificate(cert, pkey, properties) || !cert || !pkey)
        return Security::ContextPointer();

    Security::ContextPointer ctx(createSSLContext(cert, pkey, options));
    if (ctx && trusted)
        Ssl::chainCertificatesToSSLContext(ctx, options);
    return ctx;
}

void
Ssl::chainCertificatesToSSLContext(Security::ContextPointer &ctx, Security::ServerOptions &options)
{
    assert(ctx);
    // Add signing certificate to the certificates chain
    X509 *signingCert = options.signingCa.cert.get();
    if (SSL_CTX_add_extra_chain_cert(ctx.get(), signingCert)) {
        // increase the certificate lock
        X509_up_ref(signingCert);
    } else {
        const auto ssl_error = ERR_get_error();
        debugs(33, DBG_IMPORTANT, "WARNING: can not add signing certificate to SSL context chain: " << Security::ErrorString(ssl_error));
    }

    for (auto cert : options.signingCa.chain) {
        if (SSL_CTX_add_extra_chain_cert(ctx.get(), cert.get())) {
            // increase the certificate lock
            X509_up_ref(cert.get());
        } else {
            const auto error = ERR_get_error();
            debugs(83, DBG_IMPORTANT, "WARNING: can not add certificate to SSL dynamic context chain: " << Security::ErrorString(error));
        }
    }
}

void
Ssl::configureUnconfiguredSslContext(Security::ContextPointer &ctx, Ssl::CertSignAlgorithm signAlgorithm,AnyP::PortCfg &port)
{
    if (ctx && signAlgorithm == Ssl::algSignTrusted)
        Ssl::chainCertificatesToSSLContext(ctx, port.secure);
}

bool
Ssl::configureSSL(SSL *ssl, CertificateProperties const &properties, AnyP::PortCfg &port)
{
    Security::CertPointer cert;
    Security::PrivateKeyPointer pkey;
    if (!generateSslCertificate(cert, pkey, properties))
        return false;

    if (!cert)
        return false;

    if (!pkey)
        return false;

    if (!SSL_use_certificate(ssl, cert.get()))
        return false;

    if (!SSL_use_PrivateKey(ssl, pkey.get()))
        return false;

    return true;
}

bool
Ssl::configureSSLUsingPkeyAndCertFromMemory(SSL *ssl, const char *data, AnyP::PortCfg &port)
{
    Security::CertPointer cert;
    Security::PrivateKeyPointer pkey;
    if (!readCertAndPrivateKeyFromMemory(cert, pkey, data))
        return false;

    if (!cert || !pkey)
        return false;

    if (!SSL_use_certificate(ssl, cert.get()))
        return false;

    if (!SSL_use_PrivateKey(ssl, pkey.get()))
        return false;

    return true;
}

bool
Ssl::verifySslCertificate(Security::ContextPointer &ctx, CertificateProperties const &properties)
{
#if HAVE_SSL_CTX_GET0_CERTIFICATE
    X509 * cert = SSL_CTX_get0_certificate(ctx.get());
#elif SQUID_USE_SSLGETCERTIFICATE_HACK
    // SSL_get_certificate is buggy in openssl versions 1.0.1d and 1.0.1e
    // Try to retrieve certificate directly from Security::ContextPointer object
    X509 ***pCert = (X509 ***)ctx->cert;
    X509 * cert = pCert && *pCert ? **pCert : NULL;
#elif SQUID_SSLGETCERTIFICATE_BUGGY
    X509 * cert = NULL;
    assert(0);
#else
    // Temporary ssl for getting X509 certificate from SSL_CTX.
    Security::SessionPointer ssl(Security::NewSessionObject(ctx));
    X509 * cert = SSL_get_certificate(ssl.get());
#endif
    if (!cert)
        return false;
    const auto time_notBefore = X509_getm_notBefore(cert);
    const auto time_notAfter = X509_getm_notAfter(cert);
    return (X509_cmp_current_time(time_notBefore) < 0 && X509_cmp_current_time(time_notAfter) > 0);
}

void
Ssl::setClientSNI(SSL *ssl, const char *fqdn)
{
    const Ip::Address test(fqdn);
    if (!test.isAnyAddr())
        return; // raw IP is inappropriate for SNI

    //The SSL_CTRL_SET_TLSEXT_HOSTNAME is a openssl macro which indicates
    // if the TLS servername extension (SNI) is enabled in openssl library.
#if defined(SSL_CTRL_SET_TLSEXT_HOSTNAME)
    if (!SSL_set_tlsext_host_name(ssl, fqdn)) {
        const auto ssl_error = ERR_get_error();
        debugs(83, 3,  "WARNING: unable to set TLS servername extension (SNI): " <<
               Security::ErrorString(ssl_error) << "\n");
    }
#else
    debugs(83, 7,  "no support for TLS servername extension (SNI)");
#endif
}

const char *
Ssl::findIssuerUri(X509 *cert)
{
    AUTHORITY_INFO_ACCESS *info;
    if (!cert)
        return nullptr;
    info = static_cast<AUTHORITY_INFO_ACCESS *>(X509_get_ext_d2i(cert, NID_info_access, NULL, NULL));
    if (!info)
        return nullptr;

    static char uri[MAX_URL];
    uri[0] = '\0';

    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
            if (ad->location->type == GEN_URI) {
                xstrncpy(uri,
                         reinterpret_cast<const char *>(
                             ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier)
                         ),
                         sizeof(uri));
            }
            break;
        }
    }
    AUTHORITY_INFO_ACCESS_free(info);
    return uri[0] != '\0' ? uri : nullptr;
}

bool
Ssl::loadCerts(const char *certsFile, Ssl::CertsIndexedList &list)
{
    const BIO_Pointer in(BIO_new_file(certsFile, "r"));
    if (!in) {
        debugs(83, DBG_IMPORTANT, "Failed to open '" << certsFile << "' to load certificates");
        return false;
    }

    while (auto aCert = ReadX509Certificate(in)) {
        static char buffer[2048];
        X509_NAME_oneline(X509_get_subject_name(aCert.get()), buffer, sizeof(buffer));
        list.insert(std::pair<SBuf, X509 *>(SBuf(buffer), aCert.release()));
    }
    debugs(83, 4, "Loaded " << list.size() << " certificates from file: '" << certsFile << "'");
    return true;
}

/// quickly find the issuer certificate of a certificate cert in the
/// Ssl::CertsIndexedList list
static X509 *
findCertIssuerFast(Ssl::CertsIndexedList &list, X509 *cert)
{
    static char buffer[2048];

    if (X509_NAME *issuerName = X509_get_issuer_name(cert))
        X509_NAME_oneline(issuerName, buffer, sizeof(buffer));
    else
        return NULL;

    const auto ret = list.equal_range(SBuf(buffer));
    for (Ssl::CertsIndexedList::iterator it = ret.first; it != ret.second; ++it) {
        X509 *issuer = it->second;
        if (X509_check_issued(issuer, cert) == X509_V_OK) {
            return issuer;
        }
    }
    return NULL;
}

/// slowly find the issuer certificate of a given cert using linear search
static X509 *
sk_x509_findIssuer(const STACK_OF(X509) *sk, X509 *cert)
{
    if (!sk)
        return nullptr;

    const auto certCount = sk_X509_num(sk);
    for (int i = 0; i < certCount; ++i) {
        const auto issuer = sk_X509_value(sk, i);
        if (X509_check_issued(issuer, cert) == X509_V_OK)
            return issuer;
    }
    return nullptr;
}

/// finds issuer of a given certificate in CA store of the given connContext
/// \returns the cert issuer (after increasing its reference count) or nil
static X509 *
findIssuerInCaDb(X509 *cert, const Security::ContextPointer &connContext)
{
    if (!connContext)
        return nullptr;

    X509_STORE_CTX *storeCtx = X509_STORE_CTX_new();
    if (!storeCtx) {
        debugs(83, DBG_IMPORTANT, "Failed to allocate STORE_CTX object");
        return nullptr;
    }

    X509 *issuer = nullptr;
    X509_STORE *store = SSL_CTX_get_cert_store(connContext.get());
    if (X509_STORE_CTX_init(storeCtx, store, nullptr, nullptr)) {
        const auto ret = X509_STORE_CTX_get1_issuer(&issuer, storeCtx, cert);
        if (ret > 0) {
            assert(issuer);
            char buffer[256];
            debugs(83, 5, "found " << X509_NAME_oneline(X509_get_subject_name(issuer), buffer, sizeof(buffer)));
        } else {
            debugs(83, ret < 0 ? 2 : 3, "not found or failure: " << ret);
            assert(!issuer);
        }
    } else {
        const auto ssl_error = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "Failed to initialize STORE_CTX object: " << Security::ErrorString(ssl_error));
    }

    X509_STORE_CTX_free(storeCtx);

    return issuer;
}

Security::CertPointer
Ssl::findIssuerCertificate(X509 *cert, const STACK_OF(X509) *serverCertificates, const Security::ContextPointer &context)
{
    Must(cert);

    // check certificate chain, if any
    if (const auto issuer = serverCertificates ? sk_x509_findIssuer(serverCertificates, cert) : nullptr) {
        X509_up_ref(issuer);
        return Security::CertPointer(issuer);
    }

    // check untrusted certificates
    if (const auto issuer = findCertIssuerFast(SquidUntrustedCerts, cert)) {
        X509_up_ref(issuer);
        return Security::CertPointer(issuer);
    }

    // check trusted CA certificates
    if (const auto issuer = findIssuerInCaDb(cert, context)) {
        // no X509_up_ref(issuer) because findIssuerInCaDb() ups reference count
        return Security::CertPointer(issuer);
    }

    return Security::CertPointer(nullptr);
}

bool
Ssl::missingChainCertificatesUrls(std::queue<SBuf> &URIs, const STACK_OF(X509) &serverCertificates, const Security::ContextPointer &context)
{
    for (int i = 0; i < sk_X509_num(&serverCertificates); ++i) {
        const auto cert = sk_X509_value(&serverCertificates, i);

        if (findIssuerCertificate(cert, &serverCertificates, context))
            continue;

        if (const auto issuerUri = findIssuerUri(cert)) {
            URIs.push(SBuf(issuerUri));
        } else {
            static char name[2048];
            debugs(83, 3, "Issuer certificate for " <<
                   X509_NAME_oneline(X509_get_subject_name(cert), name, sizeof(name)) <<
                   " is missing and its URI is not provided");
        }
    }

    debugs(83, (URIs.empty() ? 3 : 5), "found: " << URIs.size());
    return !URIs.empty();
}

/// add missing issuer certificates to untrustedCerts
static void
completeIssuers(X509_STORE_CTX *ctx, STACK_OF(X509) &untrustedCerts)
{
    debugs(83, 2,  "completing " << sk_X509_num(&untrustedCerts) <<
           " OpenSSL untrusted certs using " << SquidUntrustedCerts.size() <<
           " configured untrusted certificates");

    const X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    int depth = X509_VERIFY_PARAM_get_depth(param);
    Security::CertPointer current;
    current.resetAndLock(X509_STORE_CTX_get0_cert(ctx));
    int i = 0;
    for (i = 0; current && (i < depth); ++i) {
        if (X509_check_issued(current.get(), current.get()) == X509_V_OK) {
            // either ctx->cert is itself self-signed or untrustedCerts
            // aready contain the self-signed current certificate
            break;
        }

        // untrustedCerts is short, not worth indexing
        const Security::ContextPointer nullCtx;
        auto issuer = Ssl::findIssuerCertificate(current.get(), &untrustedCerts, nullCtx);
        current = issuer;
        if (issuer)
            sk_X509_push(&untrustedCerts, issuer.release());
    }

    if (i >= depth)
        debugs(83, 2,  "exceeded the maximum certificate chain length: " << depth);
}

/// Validates certificates while consulting sslproxy_foreign_intermediate_certs
/// and, optionally, the given extra certificates.
/// \returns whatever OpenSSL X509_verify_cert() returns
static int
VerifyCtxCertificates(X509_STORE_CTX *ctx, STACK_OF(X509) *extraCerts)
{
    // OpenSSL already maintains ctx->untrusted but we cannot modify
    // internal OpenSSL list directly. We have to give OpenSSL our own
    // list, but it must include certificates on the OpenSSL ctx->untrusted
    STACK_OF(X509) *oldUntrusted = X509_STORE_CTX_get0_untrusted(ctx);
    // X509_chain_up_ref() increments cert references _and_ dupes the stack
    Ssl::X509_STACK_Pointer untrustedCerts(oldUntrusted ? X509_chain_up_ref(oldUntrusted) : sk_X509_new_null());

    if (extraCerts) {
        for (int i = 0; i < sk_X509_num(extraCerts); ++i) {
            const auto cert = sk_X509_value(extraCerts, i);
            X509_up_ref(cert);
            sk_X509_push(untrustedCerts.get(), cert);
        }
    }

    // If the local untrusted certificates internal database is used
    // run completeIssuers to add missing certificates if possible.
    if (SquidUntrustedCerts.size() > 0)
        completeIssuers(ctx, *untrustedCerts);

    X509_STORE_CTX_set0_untrusted(ctx, untrustedCerts.get()); // No locking/unlocking, just sets ctx->untrusted
    int ret = X509_verify_cert(ctx);
    X509_STORE_CTX_set0_untrusted(ctx, oldUntrusted); // Set back the old untrusted list
    return ret;
}

/// \interface OpenSSL_vcb_disambiguation
///
/// OpenSSL has two very different concepts with nearly identical names:
///
/// a) A (replaceable) certificate verification function -- X509_verify_cert():
///    This function drives the entire certificate verification algorithm.
///    It can be called directly, but is usually called during SSL_connect().
///    OpenSSL calls this function a "verification callback function".
///    SSL_CTX_set_cert_verify_callback(3) replaces X509_verify_cert() default.
///
/// b) An (optional) certificate verification adjustment callback:
///    This function, if set, is called at the end of (a) to adjust (a) results.
///    It is never called directly, only from (a).
///    OpenSSL calls this function a "verify_callback function".
///    The SSL_CTX_set_verify(3) family of functions sets this function.

/// Validates certificates while consulting sslproxy_foreign_intermediate_certs
/// but without using any dynamically downloaded intermediate certificates.
/// OpenSSL "verification callback function" (\ref OpenSSL_vcb_disambiguation)
static int
untrustedToStoreCtx_cb(X509_STORE_CTX *ctx, void *)
{
    debugs(83, 4, "Try to use pre-downloaded intermediate certificates");
    return VerifyCtxCertificates(ctx, nullptr);
}

void
Ssl::useSquidUntrusted(SSL_CTX *sslContext)
{
    SSL_CTX_set_cert_verify_callback(sslContext, untrustedToStoreCtx_cb, NULL);
}

bool
Ssl::loadSquidUntrusted(const char *path)
{
    return Ssl::loadCerts(path, SquidUntrustedCerts);
}

void
Ssl::unloadSquidUntrusted()
{
    if (SquidUntrustedCerts.size()) {
        for (Ssl::CertsIndexedList::iterator it = SquidUntrustedCerts.begin(); it != SquidUntrustedCerts.end(); ++it) {
            X509_free(it->second);
        }
        SquidUntrustedCerts.clear();
    }
}

bool Ssl::generateUntrustedCert(Security::CertPointer &untrustedCert, Security::PrivateKeyPointer &untrustedPkey, Security::CertPointer const  &cert, Security::PrivateKeyPointer const & pkey)
{
    // Generate the self-signed certificate, using a hard-coded subject prefix
    Ssl::CertificateProperties certProperties;
    if (const char *cn = CommonHostName(cert.get())) {
        certProperties.commonName = "Not trusted by \"";
        certProperties.commonName += cn;
        certProperties.commonName += "\"";
    } else if (const char *org = getOrganization(cert.get())) {
        certProperties.commonName =  "Not trusted by \"";
        certProperties.commonName += org;
        certProperties.commonName += "\"";
    } else
        certProperties.commonName =  "Not trusted";
    certProperties.setCommonName = true;
    // O, OU, and other CA subject fields will be mimicked
    // Expiration date and other common properties will be mimicked
    certProperties.signAlgorithm = Ssl::algSignSelf;
    certProperties.signWithPkey.resetAndLock(pkey.get());
    certProperties.mimicCert.resetAndLock(cert.get());
    return Ssl::generateSslCertificate(untrustedCert, untrustedPkey, certProperties);
}

void Ssl::InRamCertificateDbKey(const Ssl::CertificateProperties &certProperties, SBuf &key)
{
    bool origSignatureAsKey = false;
    if (certProperties.mimicCert) {
        if (auto *sig = Ssl::X509_get_signature(certProperties.mimicCert)) {
            origSignatureAsKey = true;
            key.append((const char *)sig->data, sig->length);
        }
    }

    if (!origSignatureAsKey || certProperties.setCommonName) {
        // Use common name instead
        key.append(certProperties.commonName.c_str());
    }
    key.append(certProperties.setCommonName ? '1' : '0');
    key.append(certProperties.setValidAfter ? '1' : '0');
    key.append(certProperties.setValidBefore ? '1' : '0');
    key.append(certProperties.signAlgorithm != Ssl:: algSignEnd ? certSignAlgorithm(certProperties.signAlgorithm) : "-");
    key.append(certProperties.signHash ? EVP_MD_name(certProperties.signHash) : "-");

    if (certProperties.mimicCert) {
        Ssl::BIO_Pointer bio(BIO_new_SBuf(&key));
        ASN1_item_i2d_bio(ASN1_ITEM_rptr(X509), bio.get(), (ASN1_VALUE *)certProperties.mimicCert.get());
    }
}

static int
bio_sbuf_create(BIO* bio)
{
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    return 1;
}

static int
bio_sbuf_destroy(BIO* bio)
{
    if (!bio)
        return 0;
    return 1;
}

int
bio_sbuf_write(BIO* bio, const char* data, int len)
{
    SBuf *buf = static_cast<SBuf *>(BIO_get_data(bio));
    // TODO: Convert exceptions into BIO errors
    buf->append(data, len);
    return len;
}

int
bio_sbuf_puts(BIO* bio, const char* data)
{
    // TODO: use bio_sbuf_write() instead
    SBuf *buf = static_cast<SBuf *>(BIO_get_data(bio));
    size_t oldLen = buf->length();
    buf->append(data);
    return buf->length() - oldLen;
}

long
bio_sbuf_ctrl(BIO* bio, int cmd, long num, void* ptr) {
    SBuf *buf = static_cast<SBuf *>(BIO_get_data(bio));
    switch (cmd) {
    case BIO_CTRL_RESET:
        // TODO: Convert exceptions into BIO errors
        buf->clear();
        return 1;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
}

BIO *Ssl::BIO_new_SBuf(SBuf *buf)
{
#if HAVE_LIBCRYPTO_BIO_METH_NEW
    static BIO_METHOD *BioSBufMethods = nullptr;
    if (!BioSBufMethods) {
        BioSBufMethods = BIO_meth_new(BIO_TYPE_MEM, "Squid-SBuf");
        BIO_meth_set_write(BioSBufMethods, bio_sbuf_write);
        BIO_meth_set_read(BioSBufMethods, nullptr);
        BIO_meth_set_puts(BioSBufMethods, bio_sbuf_puts);
        BIO_meth_set_gets(BioSBufMethods, nullptr);
        BIO_meth_set_ctrl(BioSBufMethods, bio_sbuf_ctrl);
        BIO_meth_set_create(BioSBufMethods, bio_sbuf_create);
        BIO_meth_set_destroy(BioSBufMethods, bio_sbuf_destroy);
    }
#else
    static BIO_METHOD *BioSBufMethods = new BIO_METHOD({
        BIO_TYPE_MEM,
        "Squid SBuf",
        bio_sbuf_write,
        nullptr,
        bio_sbuf_puts,
        nullptr,
        bio_sbuf_ctrl,
        bio_sbuf_create,
        bio_sbuf_destroy,
        NULL
    });
#endif
    BIO *bio = BIO_new(BioSBufMethods);
    Must(bio);
    BIO_set_data(bio, buf);
    BIO_set_init(bio, 1);
    return bio;
}

#endif /* USE_OPENSSL */

