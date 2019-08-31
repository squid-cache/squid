/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "fatal.h"
#include "security/CertGadgets.h"
#include "security/KeyData.h"
#include "SquidConfig.h"
#include "ssl/bio.h"
#include "ssl/gadgets.h"

/**
 * Read certificate from file.
 * See also: Ssl::ReadX509Certificate function, gadgets.cc file
 */
bool
Security::KeyData::loadX509CertFromFile()
{
    debugs(83, DBG_IMPORTANT, "Using certificate in " << certFile);
    cert.reset(); // paranoid: ensure cert is unset

#if USE_OPENSSL
    const char *certFilename = certFile.c_str();
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file()));
    if (!bio || !BIO_read_filename(bio.get(), certFilename)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate file '" << certFile << "': " << ErrorString(x));
        return false;
    }

    cert = Ssl::ReadX509Certificate(bio); // error detected/reported below

#elif USE_GNUTLS
    const char *certFilename = certFile.c_str();
    gnutls_datum_t data;
    Security::LibErrorCode x = gnutls_load_file(certFilename, &data);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate file '" << certFile << "': " << ErrorString(x));
        return false;
    }

    gnutls_pcert_st pcrt;
    x = gnutls_pcert_import_x509_raw(&pcrt, &data, GNUTLS_X509_FMT_PEM, 0);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to import certificate from '" << certFile << "': " << ErrorString(x));
        return false;
    }
    gnutls_free(data.data);

    gnutls_x509_crt_t certificate;
    x = gnutls_pcert_export_x509(&pcrt, &certificate);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to X.509 convert certificate from '" << certFile << "': " << ErrorString(x));
        return false;
    }

    if (certificate) {
        cert = Security::CertPointer(certificate, [](gnutls_x509_crt_t p) {
            debugs(83, 5, "gnutls_x509_crt_deinit cert=" << (void*)p);
            gnutls_x509_crt_deinit(p);
        });
    }

#else
    // do nothing.
#endif

    if (!cert) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate from '" << certFile << "'");
    }

    return bool(cert);
}

void
Security::KeyData::tryAddChainCa(Security::CertPointer &ca)
{
    const auto name = CertSubjectName(ca);
    ErrorCode checkCode;
#if TLS_CHAIN_NO_SELFSIGNED
    // self-signed certificates are not valid in a sent chain
    if (CertIssuerCheck(ca, ca, checkCode)) {
        debugs(83, DBG_PARSE_NOTE(2), "CA " << name << " is self-signed, will not be chained.");
        return;
    }
#endif

    CertPointer latestCert(chain.size() > 0 ? chain.front() : cert);

    // checks that the chained certs are actually part of a chain for validating cert
    if (CertIssuerCheck(latestCert, ca, checkCode)) {
        debugs(83, DBG_PARSE_NOTE(3), "Adding issuer CA: " << name);
        // OpenSSL API requires that we order certificates such that the
        // chain can be appended directly into the on-wire traffic.
        chain.emplace_back(ca);
    } else {
        debugs(83, DBG_PARSE_NOTE(2), "Ignoring non-issuer CA " << name << ": " << VerifyErrorString(checkCode) << " (" << checkCode << ")");
    }
}

/**
 * Read certificate from file.
 * See also: Ssl::ReadX509Certificate function, gadgets.cc file
 */
void
Security::KeyData::loadX509ChainFromFile()
{
    ErrorCode checkCode;
    if (CertIssuerCheck(cert, cert, checkCode)) {
        const auto name = CertSubjectName(cert);
        debugs(83, DBG_PARSE_NOTE(2), "Certificate is self-signed, will not be chained: " << name);
        return;
    }

    debugs(83, DBG_PARSE_NOTE(2), "Using certificate chain in " << certFile);
    // and add to the chain any other certificate exist in the file
#if USE_OPENSSL
    const char *certFilename = certFile.c_str();
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file()));
    if (!bio || !BIO_read_filename(bio.get(), certFilename)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load chain file '" << certFile << "': " << ErrorString(x));
        return;
    }

    while (auto ca = CertPointer(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))) {
        tryAddChainCa(ca);
    }

#elif USE_GNUTLS
    const char *certFilename = certFile.c_str();
    gnutls_datum_t data;
    Security::ErrorCode x = gnutls_load_file(certFilename, &data);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load chain file '" << certFile << "': " << ErrorString(x));
        return;
    }

    unsigned int listSz = 0;
    gnutls_x509_crt_t *certChain;
    x = gnutls_x509_crt_list_import2(&certChain, &listSz, &data, GNUTLS_X509_FMT_PEM, 0);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to import chain file '" << certFile << "': " << ErrorString(x));
        return;
    }

    for (unsigned int i = 0; i < listSz ; ++i) {
        CertPointer ca = Security::CertPointer(certChain[i], [](gnutls_x509_crt_t p) {
            debugs(83, 5, "gnutls_x509_crt_deinit cert=" << (void*)p);
            gnutls_x509_crt_deinit(p);
        });

        tryAddChainCa(ca);
    }
    gnutls_free(certChain);

#else
    debugs(83, DBG_PARSE_NOTE(2), "ERROR: Loading certificate chain from PEM files requires OpenSSL or GnuTLS.");
#endif
}

/**
 * Read X.509 private key from file.
 */
bool
Security::KeyData::loadX509PrivateKeyFromFile()
{
    debugs(83, DBG_IMPORTANT, "Using key in " << privateKeyFile);

#if USE_OPENSSL
    const char *keyFilename = privateKeyFile.c_str();
    // XXX: Ssl::AskPasswordCb needs SSL_CTX_set_default_passwd_cb_userdata()
    // so this may not fully work iff Config.Program.ssl_password is set.
    pem_password_cb *cb = ::Config.Program.ssl_password ? &Ssl::AskPasswordCb : nullptr;
    Ssl::ReadPrivateKeyFromFile(keyFilename, pkey, cb);

    if (pkey && !X509_check_private_key(cert.get(), pkey.get())) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << privateKeyFile << "' X509_check_private_key() failed");
        pkey.reset();
    }

#elif USE_GNUTLS
    const char *keyFilename = privateKeyFile.c_str();
    gnutls_datum_t data;
    if (gnutls_load_file(keyFilename, &data) == GNUTLS_E_SUCCESS) {
        gnutls_privkey_t key;
        (void)gnutls_privkey_init(&key);
        Security::ErrorCode x = gnutls_privkey_import_x509_raw(key, &data, GNUTLS_X509_FMT_PEM, nullptr, 0);
        if (x == GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_t xkey;
            gnutls_privkey_export_x509(key, &xkey);
            gnutls_privkey_deinit(key);
            pkey = Security::PrivateKeyPointer(xkey, [](gnutls_x509_privkey_t p) {
                debugs(83, 5, "gnutls_x509_privkey_deinit pkey=" << (void*)p);
                gnutls_x509_privkey_deinit(p);
            });
        }
    }
    gnutls_free(data.data);

#else
    // nothing to do.
#endif

    return bool(pkey);
}

void
Security::KeyData::loadFromFiles(const AnyP::PortCfg &port, const char *portType)
{
    char buf[128];
    if (!loadX509CertFromFile()) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing certificate in '" << certFile << "'");
        return;
    }

    // certificate chain in the PEM file is optional
    loadX509ChainFromFile();

    // pkey is mandatory, not having it makes cert and chain pointless.
    if (!loadX509PrivateKeyFromFile()) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing private key in '" << privateKeyFile << "'");
        cert.reset();
        chain.clear();
    }
}

