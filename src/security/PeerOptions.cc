/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
#include "parser/Tokenizer.h"
#include "Parsing.h"
#include "security/PeerOptions.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

Security::PeerOptions Security::ProxyOutgoingConfig;

Security::PeerOptions::PeerOptions(const Security::PeerOptions &p) :
    certFile(p.certFile),
    privateKeyFile(p.privateKeyFile),
    sslOptions(p.sslOptions),
    caFile(p.caFile),
    caDir(p.caDir),
    crlFile(p.crlFile),
    sslCipher(p.sslCipher),
    sslFlags(p.sslFlags),
    sslDomain(p.sslDomain),
    parsedOptions(p.parsedOptions),
    parsedFlags(p.parsedFlags),
    sslVersion(p.sslVersion),
    encryptTransport(p.encryptTransport)
{
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
        certFile = SBuf(token + 5);
        if (privateKeyFile.isEmpty())
            privateKeyFile = certFile;
    } else if (strncmp(token, "key=", 4) == 0) {
        privateKeyFile = SBuf(token + 4);
        if (certFile.isEmpty()) {
            debugs(3, DBG_PARSE_NOTE(1), "WARNING: cert= option needs to be set before key= is used.");
            certFile = privateKeyFile;
        }
    } else if (strncmp(token, "version=", 8) == 0) {
        debugs(0, DBG_PARSE_NOTE(1), "UPGRADE WARNING: SSL version= is deprecated. Use options= to limit protocols instead.");
        sslVersion = xatoi(token + 8);
    } else if (strncmp(token, "min-version=", 12) == 0) {
        tlsMinVersion = SBuf(token + 12);
    } else if (strncmp(token, "options=", 8) == 0) {
        sslOptions = SBuf(token + 8);
        parsedOptions = parseOptions();
    } else if (strncmp(token, "cipher=", 7) == 0) {
        sslCipher = SBuf(token + 7);
    } else if (strncmp(token, "cafile=", 7) == 0) {
        caFile = SBuf(token + 7);
    } else if (strncmp(token, "capath=", 7) == 0) {
        caDir = SBuf(token + 7);
    } else if (strncmp(token, "crlfile=", 8) == 0) {
        crlFile = SBuf(token + 8);
    } else if (strncmp(token, "flags=", 6) == 0) {
        if (parsedFlags != 0) {
            debugs(3, DBG_PARSE_NOTE(1), "WARNING: Overwriting flags=" << sslFlags << " with " << SBuf(token + 6));
        }
        sslFlags = SBuf(token + 6);
        parsedFlags = parseFlags();
    } else if (strncmp(token, "domain=", 7) == 0) {
        sslDomain = SBuf(token + 7);
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

    if (!certFile.isEmpty())
        p->appendf(" %scert=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(certFile));

    if (!privateKeyFile.isEmpty() && privateKeyFile != certFile)
        p->appendf(" %skey=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(privateKeyFile));

    if (!sslOptions.isEmpty())
        p->appendf(" %soptions=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(sslOptions));

    if (!sslCipher.isEmpty())
        p->appendf(" %scipher=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(sslCipher));

    if (!caFile.isEmpty())
        p->appendf(" %scafile=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(caFile));

    if (!caDir.isEmpty())
        p->appendf(" %scapath=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(caDir));

    if (!crlFile.isEmpty())
        p->appendf(" %scrlfile=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(crlFile));

    if (!sslFlags.isEmpty())
        p->appendf(" %sflags=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(sslFlags));
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

        } else {
            debugs(0, DBG_PARSE_NOTE(1), "WARNING: Unknown TLS minimum version: " << tlsMinVersion);
        }

    } else if (sslVersion > 2) {
        // backward compatibility hack for sslversion= configuration
        // only use if tls-min-version=N.N is not present
        // values 0-2 for auto and SSLv2 are not supported any longer.
        // Do it this way so we DO cause changes to options= in cachemgr config report
        const char *add = NULL;
        switch (sslVersion) {
        case 3:
            add = "NO_TLSv1,NO_TLSv1_1,NO_TLSv1_2";
            break;
        case 4:
            add = "NO_SSLv3,NO_TLSv1_1,NO_TLSv1_2";
            break;
        case 5:
            add = "NO_SSLv3,NO_TLSv1,NO_TLSv1_2";
            break;
        case 6:
            add = "NO_SSLv3,NO_TLSv1,NO_TLSv1_1";
            break;
        default: // nothing
            break;
        }
        if (add) {
            if (!sslOptions.isEmpty())
                sslOptions.append(",",1);
            sslOptions.append(add, strlen(add));
        }
        sslVersion = 0; // prevent sslOptions being repeatedly appended
    }
}

// XXX: make a GnuTLS variant
Security::ContextPointer
Security::PeerOptions::createClientContext(bool setOptions)
{
    Security::ContextPointer t = NULL;

    updateTlsVersionLimits();
#if USE_OPENSSL
    // XXX: temporary performance regression. c_str() data copies and prevents this being a const method
    t = sslCreateClientContext(certFile.c_str(), privateKeyFile.c_str(), sslCipher.c_str(),
                               (setOptions ? parsedOptions : 0), parsedFlags,
                               caFile.c_str(), caDir.c_str(), crlFile.c_str());
#endif

    return t;
}

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

/**
 * Pre-parse TLS options= parameter to be applied when the TLS objects created.
 * Options must not used in the case of peek or stare bump mode.
 */
long
Security::PeerOptions::parseOptions()
{
    long op = 0;
    ::Parser::Tokenizer tok(sslOptions);

    do {
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

        if (tok.int64(hex, 16, false)) {
            /* Special case.. hex specification */
            value = hex;
        }

        else if (tok.prefix(option, optChars)) {
            // find the named option in our supported set
            for (struct ssl_option *opttmp = ssl_options; opttmp->name; ++opttmp) {
                if (option.cmp(opttmp->name) == 0) {
                    value = opttmp->value;
                    break;
                }
            }
        }

        if (!value) {
            fatalf("Unknown TLS option '" SQUIDSBUFPH "'", SQUIDSBUFPRINT(option));
        }

        switch (mode) {

        case MODE_ADD:
            op |= value;
            break;

        case MODE_REMOVE:
            op &= ~value;
            break;
        }

        static const CharacterSet delims("TLS-option-delim",":,");
        if (!tok.skipAll(delims) && !tok.atEnd()) {
            fatalf("Unknown TLS option '" SQUIDSBUFPH "'", SQUIDSBUFPRINT(tok.remaining()));
        }

    } while (!tok.atEnd());

#if SSL_OP_NO_SSLv2
    // compliance with RFC 6176: Prohibiting Secure Sockets Layer (SSL) Version 2.0
    op = op | SSL_OP_NO_SSLv2;
#endif
    return op;
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
            if (tok.skip(flagTokens[i].label) == 0) {
                found = flagTokens[i].mask;
                break;
            }
        }
        if (!found)
            fatalf("Unknown TLS flag '" SQUIDSBUFPH "'", SQUIDSBUFPRINT(tok.remaining()));
        fl |= found;
    } while (tok.skipOne(delims));

    return fl;
}

void
parse_securePeerOptions(Security::PeerOptions *opt)
{
    while(const char *token = ConfigParser::NextToken())
        opt->parse(token);
}

