/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Packable.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"
#include "parser/Tokenizer.h"
#include "Parsing.h"
#include "security/PeerOptions.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

Security::PeerOptions Security::ProxyOutgoingConfig;

Security::PeerOptions::PeerOptions()
{
    // init options consistent with an empty sslOptions
    parseOptions();
}

void
Security::PeerOptions::parse(const char *token)
{
    if (!*token) {
        // config says just "ssl" or "tls" (or "tls-")
        encryptTransport = true;
        return;
    }

    if (strncmp(token, "disable", 7) == 0) {
        clear();
        return;
    }

    if (strncmp(token, "cert=", 5) == 0) {
        KeyData t;
        t.privateKeyFile = t.certFile = SBuf(token + 5);
        certs.emplace_back(t);
    } else if (strncmp(token, "key=", 4) == 0) {
        if (certs.empty() || certs.back().certFile.isEmpty()) {
            fatal("cert= option must be set before key= is used.");
            return;
        }
        KeyData &t = certs.back();
        t.privateKeyFile = SBuf(token + 4);
    } else if (strncmp(token, "version=", 8) == 0) {
        debugs(0, DBG_PARSE_NOTE(1), "UPGRADE WARNING: SSL version= is deprecated. Use options= to limit protocols instead.");
        sslVersion = xatoi(token + 8);
    } else if (strncmp(token, "min-version=", 12) == 0) {
        tlsMinVersion = SBuf(token + 12);
    } else if (strncmp(token, "options=", 8) == 0) {
        sslOptions = SBuf(token + 8);
        parseOptions();
    } else if (strncmp(token, "cipher=", 7) == 0) {
        sslCipher = SBuf(token + 7);
    } else if (strncmp(token, "cafile=", 7) == 0) {
        caFiles.emplace_back(SBuf(token + 7));
    } else if (strncmp(token, "capath=", 7) == 0) {
        caDir = SBuf(token + 7);
#if !USE_OPENSSL
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: capath= option requires --with-openssl.");
#endif
    } else if (strncmp(token, "crlfile=", 8) == 0) {
        crlFile = SBuf(token + 8);
        loadCrlFile();
    } else if (strncmp(token, "flags=", 6) == 0) {
        if (parsedFlags != 0) {
            debugs(3, DBG_PARSE_NOTE(1), "WARNING: Overwriting flags=" << sslFlags << " with " << SBuf(token + 6));
        }
        sslFlags = SBuf(token + 6);
        parsedFlags = parseFlags();
    } else if (strncmp(token, "default-ca=off", 14) == 0 || strncmp(token, "no-default-ca", 13) == 0) {
        if (flags.tlsDefaultCa.configured() && flags.tlsDefaultCa)
            fatalf("ERROR: previous default-ca settings conflict with %s", token);
        flags.tlsDefaultCa.configure(false);
    } else if (strncmp(token, "default-ca=on", 13) == 0 || strncmp(token, "default-ca", 10) == 0) {
        if (flags.tlsDefaultCa.configured() && !flags.tlsDefaultCa)
            fatalf("ERROR: previous default-ca settings conflict with %s", token);
        flags.tlsDefaultCa.configure(true);
    } else if (strncmp(token, "domain=", 7) == 0) {
        sslDomain = SBuf(token + 7);
    } else if (strncmp(token, "no-npn", 6) == 0) {
        flags.tlsNpn = false;
    } else {
        debugs(3, DBG_CRITICAL, "ERROR: Unknown TLS option '" << token << "'");
        return;
    }

    encryptTransport = true;
}

void
Security::PeerOptions::dumpCfg(Packable *p, const char *pfx) const
{
    if (!encryptTransport) {
        p->appendf(" %sdisable", pfx);
        return; // no other settings are relevant
    }

    for (auto &i : certs) {
        if (!i.certFile.isEmpty())
            p->appendf(" %scert=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(i.certFile));

        if (!i.privateKeyFile.isEmpty() && i.privateKeyFile != i.certFile)
            p->appendf(" %skey=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(i.privateKeyFile));
    }

    if (!sslOptions.isEmpty())
        p->appendf(" %soptions=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(sslOptions));

    if (!sslCipher.isEmpty())
        p->appendf(" %scipher=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(sslCipher));

    for (auto i : caFiles) {
        p->appendf(" %scafile=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(i));
    }

    if (!caDir.isEmpty())
        p->appendf(" %scapath=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(caDir));

    if (!crlFile.isEmpty())
        p->appendf(" %scrlfile=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(crlFile));

    if (!sslFlags.isEmpty())
        p->appendf(" %sflags=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(sslFlags));

    if (flags.tlsDefaultCa.configured()) {
        // default ON for peers / upstream servers
        // default OFF for listening ports
        if (flags.tlsDefaultCa)
            p->appendf(" %sdefault-ca", pfx);
        else
            p->appendf(" %sdefault-ca=off", pfx);
    }

    if (!flags.tlsNpn)
        p->appendf(" %sno-npn", pfx);
}

void
Security::PeerOptions::updateTlsVersionLimits()
{
    if (!tlsMinVersion.isEmpty()) {
        ::Parser::Tokenizer tok(tlsMinVersion);
        int64_t v = 0;
        if (tok.skip('1') && tok.skip('.') && tok.int64(v, 10, false, 1) && v <= 3) {
            // only account for TLS here - SSL versions are handled by options= parameter
            // avoid affecting options= parameter in cachemgr config report
#if USE_OPENSSL
#if SSL_OP_NO_TLSv1
            if (v > 0)
                parsedOptions |= SSL_OP_NO_TLSv1;
#endif
#if SSL_OP_NO_TLSv1_1
            if (v > 1)
                parsedOptions |= SSL_OP_NO_TLSv1_1;
#endif
#if SSL_OP_NO_TLSv1_2
            if (v > 2)
                parsedOptions |= SSL_OP_NO_TLSv1_2;
#endif

#elif USE_GNUTLS
            // XXX: update parsedOptions directly to avoid polluting 'options=' dumps
            SBuf add;
            if (v > 0)
                add.append(":-VERS-TLS1.0");
            if (v > 1)
                add.append(":-VERS-TLS1.1");
            if (v > 2)
                add.append(":-VERS-TLS1.2");

            if (sslOptions.isEmpty())
                add.chop(1); // remove the initial ':'
            sslOptions.append(add);
#endif

        } else {
            debugs(0, DBG_PARSE_NOTE(1), "WARNING: Unknown TLS minimum version: " << tlsMinVersion);
        }

        return;
    }

    if (sslVersion > 2) {
        // backward compatibility hack for sslversion= configuration
        // only use if tls-min-version=N.N is not present
        // values 0-2 for auto and SSLv2 are not supported any longer.
        // Do it this way so we DO cause changes to options= in cachemgr config report
        const char *add = nullptr;
        switch (sslVersion) {
        case 3:
#if USE_OPENSSL
            parsedOptions |= (SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2);
#elif USE_GNUTLS
            add = ":-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2";
#endif
            break;
        case 4:
#if USE_OPENSSL
            parsedOptions |= (SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2);
#elif USE_GNUTLS
            add = ":+VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2";
#endif
            break;
        case 5:
#if USE_OPENSSL
            parsedOptions |= (SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_2);
#elif USE_GNUTLS
            add = ":-VERS-TLS1.0:+VERS-TLS1.1:-VERS-TLS1.2";
#endif
            break;
        case 6:
#if USE_OPENSSL
            parsedOptions |= (SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);
#elif USE_GNUTLS
            add = ":-VERS-TLS1.0:-VERS-TLS1.1";
#endif
            break;
        default: // nothing
            break;
        }
        if (add) {
#if USE_GNUTLS // dont bother otherwise
            if (sslOptions.isEmpty())
                sslOptions.append(add+1, strlen(add+1));
            else
                sslOptions.append(add, strlen(add));
#endif
        }
        sslVersion = 0; // prevent sslOptions being repeatedly appended
    }
}

Security::ContextPointer
Security::PeerOptions::createBlankContext() const
{
    Security::ContextPointer ctx;
#if USE_OPENSSL
    Ssl::Initialize();

#if HAVE_OPENSSL_TLS_CLIENT_METHOD
    SSL_CTX *t = SSL_CTX_new(TLS_client_method());
#else
    SSL_CTX *t = SSL_CTX_new(SSLv23_client_method());
#endif
    if (!t) {
        const auto x = ERR_get_error();
        fatalf("Failed to allocate TLS client context: %s\n", Security::ErrorString(x));
    }
    ctx = convertContextFromRawPtr(t);

#elif USE_GNUTLS
    // Initialize for X.509 certificate exchange
    gnutls_certificate_credentials_t t;
    if (const int x = gnutls_certificate_allocate_credentials(&t)) {
        fatalf("Failed to allocate TLS client context: %s\n", Security::ErrorString(x));
    }
    ctx = convertContextFromRawPtr(t);

#else
    debugs(83, 1, "WARNING: Failed to allocate TLS client context: No TLS library");

#endif

    return ctx;
}

Security::ContextPointer
Security::PeerOptions::createClientContext(bool setOptions)
{
    updateTlsVersionLimits();

    Security::ContextPointer t(createBlankContext());
    if (t) {
#if USE_OPENSSL
        // NP: GnuTLS uses 'priorities' which are set per-session instead.
        SSL_CTX_set_options(t.get(), (setOptions ? parsedOptions : 0));

        // XXX: temporary performance regression. c_str() data copies and prevents this being a const method
        Ssl::InitClientContext(t, *this, parsedFlags);
#endif
        updateContextNpn(t);
        updateContextCa(t);
        updateContextCrl(t);
    }

    return t;
}

#if USE_OPENSSL
/// set of options we can parse and what they map to
static struct ssl_option {
    const char *name;
    long value;

} ssl_options[] = {

#if SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    {
        "NETSCAPE_REUSE_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    },
#endif
#if SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    {
        "SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    },
#endif
#if SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    {
        "MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    },
#endif
#if SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    {
        "SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    },
#endif
#if SSL_OP_TLS_D5_BUG
    {
        "TLS_D5_BUG", SSL_OP_TLS_D5_BUG
    },
#endif
#if SSL_OP_TLS_BLOCK_PADDING_BUG
    {
        "TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG
    },
#endif
#if SSL_OP_TLS_ROLLBACK_BUG
    {
        "TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG
    },
#endif
#if SSL_OP_ALL
    {
        "ALL", (long)SSL_OP_ALL
    },
#endif
#if SSL_OP_SINGLE_DH_USE
    {
        "SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE
    },
#endif
#if SSL_OP_EPHEMERAL_RSA
    {
        "EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA
    },
#endif
#if SSL_OP_PKCS1_CHECK_1
    {
        "PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1
    },
#endif
#if SSL_OP_PKCS1_CHECK_2
    {
        "PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2
    },
#endif
#if SSL_OP_NETSCAPE_CA_DN_BUG
    {
        "NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG
    },
#endif
#if SSL_OP_NON_EXPORT_FIRST
    {
        "NON_EXPORT_FIRST", SSL_OP_NON_EXPORT_FIRST
    },
#endif
#if SSL_OP_CIPHER_SERVER_PREFERENCE
    {
        "CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE
    },
#endif
#if SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
    {
        "NETSCAPE_DEMO_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
    },
#endif
#if SSL_OP_NO_SSLv3
    {
        "NO_SSLv3", SSL_OP_NO_SSLv3
    },
#endif
#if SSL_OP_NO_TLSv1
    {
        "NO_TLSv1", SSL_OP_NO_TLSv1
    },
#endif
#if SSL_OP_NO_TLSv1_1
    {
        "NO_TLSv1_1", SSL_OP_NO_TLSv1_1
    },
#endif
#if SSL_OP_NO_TLSv1_2
    {
        "NO_TLSv1_2", SSL_OP_NO_TLSv1_2
    },
#endif
#if SSL_OP_NO_COMPRESSION
    {
        "No_Compression", SSL_OP_NO_COMPRESSION
    },
#endif
#if SSL_OP_NO_TICKET
    {
        "NO_TICKET", SSL_OP_NO_TICKET
    },
#endif
#if SSL_OP_SINGLE_ECDH_USE
    {
        "SINGLE_ECDH_USE", SSL_OP_SINGLE_ECDH_USE
    },
#endif
    {
        "", 0
    },
    {
        NULL, 0
    }
};
#endif /* USE_OPENSSL */

/**
 * Pre-parse TLS options= parameter to be applied when the TLS objects created.
 * Options must not used in the case of peek or stare bump mode.
 */
void
Security::PeerOptions::parseOptions()
{
#if USE_OPENSSL
    ::Parser::Tokenizer tok(sslOptions);
    long op = 0;

    while (!tok.atEnd()) {
        enum {
            MODE_ADD, MODE_REMOVE
        } mode;

        if (tok.skip('-') || tok.skip('!'))
            mode = MODE_REMOVE;
        else {
            (void)tok.skip('+'); // default action is add. ignore if missing operator
            mode = MODE_ADD;
        }

        static const CharacterSet optChars = CharacterSet("TLS-option", "_") + CharacterSet::ALPHA + CharacterSet::DIGIT;
        int64_t hex = 0;
        SBuf option;
        long value = 0;

        // Bug 4429: identify the full option name before determining text or numeric
        if (tok.prefix(option, optChars)) {

            // find the named option in our supported set
            for (struct ssl_option *opttmp = ssl_options; opttmp->name; ++opttmp) {
                if (option.cmp(opttmp->name) == 0) {
                    value = opttmp->value;
                    break;
                }
            }

            // Special case.. hex specification
            ::Parser::Tokenizer tmp(option);
            if (!value && tmp.int64(hex, 16, false) && tmp.atEnd()) {
                value = hex;
            }
        }

        if (value) {
            switch (mode) {
            case MODE_ADD:
                op |= value;
                break;
            case MODE_REMOVE:
                op &= ~value;
                break;
            }
        } else {
            debugs(83, DBG_PARSE_NOTE(1), "ERROR: Unknown TLS option " << option);
        }

        static const CharacterSet delims("TLS-option-delim",":,");
        if (!tok.skipAll(delims) && !tok.atEnd()) {
            fatalf("Unknown TLS option '" SQUIDSBUFPH "'", SQUIDSBUFPRINT(tok.remaining()));
        }

    }

#if SSL_OP_NO_SSLv2
    // compliance with RFC 6176: Prohibiting Secure Sockets Layer (SSL) Version 2.0
    op = op | SSL_OP_NO_SSLv2;
#endif
    parsedOptions = op;

#elif USE_GNUTLS
    if (sslOptions.isEmpty()) {
        parsedOptions.reset();
        return;
    }

    const char *err = nullptr;
    const char *priorities = sslOptions.c_str();
    gnutls_priority_t op;
    if (gnutls_priority_init(&op, priorities, &err) != GNUTLS_E_SUCCESS) {
        fatalf("Unknown TLS option '%s'", err);
    }
    parsedOptions = Security::ParsedOptions(op, [](gnutls_priority_t p) {
        debugs(83, 5, "gnutls_priority_deinit p=" << (void*)p);
        gnutls_priority_deinit(p);
    });
#endif
}

/**
 * Parses the TLS flags squid.conf parameter
 */
long
Security::PeerOptions::parseFlags()
{
    if (sslFlags.isEmpty())
        return 0;

    static struct {
        SBuf label;
        long mask;
    } flagTokens[] = {
        { SBuf("NO_DEFAULT_CA"), SSL_FLAG_NO_DEFAULT_CA },
        { SBuf("DELAYED_AUTH"), SSL_FLAG_DELAYED_AUTH },
        { SBuf("DONT_VERIFY_PEER"), SSL_FLAG_DONT_VERIFY_PEER },
        { SBuf("DONT_VERIFY_DOMAIN"), SSL_FLAG_DONT_VERIFY_DOMAIN },
        { SBuf("NO_SESSION_REUSE"), SSL_FLAG_NO_SESSION_REUSE },
#if X509_V_FLAG_CRL_CHECK
        { SBuf("VERIFY_CRL"), SSL_FLAG_VERIFY_CRL },
        { SBuf("VERIFY_CRL_ALL"), SSL_FLAG_VERIFY_CRL_ALL },
#endif
        { SBuf(), 0 }
    };

    ::Parser::Tokenizer tok(sslFlags);
    static const CharacterSet delims("Flag-delimiter", ":,");

    long fl = 0;
    do {
        long found = 0;
        for (size_t i = 0; flagTokens[i].mask; ++i) {
            if (tok.skip(flagTokens[i].label)) {
                found = flagTokens[i].mask;
                break;
            }
        }
        if (!found)
            fatalf("Unknown TLS flag '" SQUIDSBUFPH "'", SQUIDSBUFPRINT(tok.remaining()));
        if (found == SSL_FLAG_NO_DEFAULT_CA) {
            if (flags.tlsDefaultCa.configured() && flags.tlsDefaultCa)
                fatal("ERROR: previous default-ca settings conflict with sslflags=NO_DEFAULT_CA");
            debugs(83, DBG_PARSE_NOTE(2), "WARNING: flags=NO_DEFAULT_CA is deprecated. Use tls-default-ca=off instead.");
            flags.tlsDefaultCa.configure(false);
        } else
            fl |= found;
    } while (tok.skipOne(delims));

    return fl;
}

/// Load a CRLs list stored in the file whose /path/name is in crlFile
/// replaces any CRL loaded previously
void
Security::PeerOptions::loadCrlFile()
{
    parsedCrl.clear();
    if (crlFile.isEmpty())
        return;

#if USE_OPENSSL
    BIO *in = BIO_new_file(crlFile.c_str(), "r");
    if (!in) {
        debugs(83, 2, "WARNING: Failed to open CRL file " << crlFile);
        return;
    }

    while (X509_CRL *crl = PEM_read_bio_X509_CRL(in,NULL,NULL,NULL)) {
        parsedCrl.emplace_back(Security::CrlPointer(crl));
    }
    BIO_free(in);
#endif
}

#if USE_OPENSSL && defined(TLSEXT_TYPE_next_proto_neg)
// Dummy next_proto_neg callback
static int
ssl_next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char supported_protos[] = {8, 'h','t','t', 'p', '/', '1', '.', '1'};
    (void)SSL_select_next_proto(out, outlen, in, inlen, supported_protos, sizeof(supported_protos));
    return SSL_TLSEXT_ERR_OK;
}
#endif

void
Security::PeerOptions::updateContextNpn(Security::ContextPointer &ctx)
{
    if (!flags.tlsNpn)
        return;

#if USE_OPENSSL && defined(TLSEXT_TYPE_next_proto_neg)
    SSL_CTX_set_next_proto_select_cb(ctx.get(), &ssl_next_proto_cb, nullptr);
#endif

    // NOTE: GnuTLS does not support the obsolete NPN extension.
    //       it does support ALPN per-session, not per-context.
}

static const char *
loadSystemTrustedCa(Security::ContextPointer &ctx)
{
    debugs(83, 8, "Setting default system Trusted CA. ctx=" << (void*)ctx.get());
#if USE_OPENSSL
    if (SSL_CTX_set_default_verify_paths(ctx.get()) == 0)
        return Security::ErrorString(ERR_get_error());

#elif USE_GNUTLS
    auto x = gnutls_certificate_set_x509_system_trust(ctx.get());
    if (x < 0)
        return Security::ErrorString(x);

#endif
    return nullptr;
}

void
Security::PeerOptions::updateContextCa(Security::ContextPointer &ctx)
{
    debugs(83, 8, "Setting CA certificate locations.");
#if USE_OPENSSL
    const char *path = caDir.isEmpty() ? nullptr : caDir.c_str();
#endif
    for (auto i : caFiles) {
#if USE_OPENSSL
        if (!SSL_CTX_load_verify_locations(ctx.get(), i.c_str(), path)) {
            const auto x = ERR_get_error();
            debugs(83, DBG_IMPORTANT, "WARNING: Ignoring error setting CA certificate location " <<
                   i << ": " << Security::ErrorString(x));
        }
#elif USE_GNUTLS
        const auto x = gnutls_certificate_set_x509_trust_file(ctx.get(), i.c_str(), GNUTLS_X509_FMT_PEM);
        if (x < 0) {
            debugs(83, DBG_IMPORTANT, "WARNING: Ignoring error setting CA certificate location " <<
                   i << ": " << Security::ErrorString(x));
        }
#endif
    }

    if (!flags.tlsDefaultCa)
        return;

    if (const char *err = loadSystemTrustedCa(ctx)) {
        debugs(83, DBG_IMPORTANT, "WARNING: Ignoring error setting default trusted CA : " << err);
    }
}

void
Security::PeerOptions::updateContextCrl(Security::ContextPointer &ctx)
{
#if USE_OPENSSL
    bool verifyCrl = false;
    X509_STORE *st = SSL_CTX_get_cert_store(ctx.get());
    if (parsedCrl.size()) {
        for (auto &i : parsedCrl) {
            if (!X509_STORE_add_crl(st, i.get()))
                debugs(83, 2, "WARNING: Failed to add CRL");
            else
                verifyCrl = true;
        }
    }

#if X509_V_FLAG_CRL_CHECK
    if ((parsedFlags & SSL_FLAG_VERIFY_CRL_ALL))
        X509_STORE_set_flags(st, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
    else if (verifyCrl || (parsedFlags & SSL_FLAG_VERIFY_CRL))
        X509_STORE_set_flags(st, X509_V_FLAG_CRL_CHECK);
#endif

#endif /* USE_OPENSSL */
}

void
Security::PeerOptions::updateSessionOptions(Security::SessionPointer &s)
{
#if USE_OPENSSL
    // 'options=' value being set to session is a GnuTLS specific thing.
#elif USE_GNUTLS
    int x;
    SBuf errMsg;
    if (!parsedOptions) {
        debugs(83, 5, "set GnuTLS default priority/options for session=" << s);
        x = gnutls_set_default_priority(s.get());
        static const SBuf defaults("default");
        errMsg = defaults;
    } else {
        debugs(83, 5, "set GnuTLS options '" << sslOptions << "' for session=" << s);
        x = gnutls_priority_set(s.get(), parsedOptions.get());
        errMsg = sslOptions;
    }

    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: Failed to set TLS options (" << errMsg << "). error: " << Security::ErrorString(x));
    }
#endif
}

void
parse_securePeerOptions(Security::PeerOptions *opt)
{
    while(const char *token = ConfigParser::NextToken())
        opt->parse(token);
}

