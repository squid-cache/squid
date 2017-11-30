/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "fatal.h"
#include "security/KeyData.h"
#include "SquidConfig.h"
#include "ssl/bio.h"

/// verify that a private key and cert match
bool
Security::KeyData::checkPrivateKey()
{
#if USE_OPENSSL
    return X509_check_private_key(cert.get(), pkey.get());
#elif USE_GNUTLS
    return true; // TODO find GnuTLS equivalent check
#else
    return false;
#endif
}

/**
 * Read certificate from file.
 * See also: Ssl::ReadX509Certificate function, gadgets.cc file
 */
bool
Security::KeyData::loadX509CertFromFile()
{
#if USE_OPENSSL
    const char *certFilename = certFile.c_str();
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file()));
    if (!bio || !BIO_read_filename(bio.get(), certFilename)) {
        const auto x = ERR_get_error();
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load file '" << certFile << "': " << ErrorString(x));
        return false;
    }

    X509 *certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);

#elif USE_GNUTLS
    const char *certFilename = certFile.c_str();
    gnutls_datum_t data;
    Security::ErrorCode x = gnutls_load_file(certFilename, &data);
    if (x != GNUTLS_E_SUCCESS) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load file '" << certFile << "': " << ErrorString(x));
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
        certificate = nullptr; // paranoid: just in case the *_t ptr is undefined after deinit.
    }
#else
    // to simplify and prevent 'undefined variable errors' in the next code block
    void *certificate = nullptr;
#endif

    if (certificate) {
#if USE_OPENSSL
        if (X509_check_issued(certificate, certificate) == X509_V_OK)
            debugs(83, 5, "Certificate is self-signed, will not be chained");
        else {
            cert.resetWithoutLocking(certificate);
            // and add to the chain any other certificate exist in the file
            while (X509 *ca = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))
                chain.emplace_front(Security::CertPointer(ca));
        }
#elif USE_GNUTLS
        cert = Security::CertPointer(certificate, [](gnutls_x509_crt_t p) {
                   debugs(83, 5, "gnutls_x509_crt_deinit cert=" << (void*)p);
                   gnutls_x509_crt_deinit(p);
               });
        // XXX: do chain load and cert self-signed check like OpenSSL
#endif

    } else {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate from '" << certFile << "'");
        cert.reset(); // paranoid: ensure cert is unset
    }

    return bool(cert);
}

void
Security::KeyData::loadFromFiles(const AnyP::PortCfg &port, const char *portType)
{
    char buf[128];
    debugs(83, DBG_IMPORTANT, "Using certificate in " << certFile);

    if (!loadX509CertFromFile()) {
#if USE_OPENSSL
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing certificate in '" << certFile << "'");
#else
        fatalf("Directive '%s_port %s' requires --with-openssl to load %s.", portType, port.s.toUrl(buf, sizeof(buf)), certFile.c_str());
#endif
        return;
    }

    const char *keyFilename = privateKeyFile.c_str();

#if USE_OPENSSL
    // XXX: Ssl::AskPasswordCb needs SSL_CTX_set_default_passwd_cb_userdata()
    // so this may not fully work iff Config.Program.ssl_password is set.
    pem_password_cb *cb = ::Config.Program.ssl_password ? &Ssl::AskPasswordCb : nullptr;
    Ssl::ReadPrivateKeyFromFile(keyFilename, pkey, cb);

#elif USE_GNUTLS
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
#endif

    if (!pkey) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing private key in '" << keyFilename << "'");
    } else if (!checkPrivateKey()) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' checkPrivateKey() failed");
    } else
        return; // everything is okay

    pkey.reset();
    cert.reset();
}
