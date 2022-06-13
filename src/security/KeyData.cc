/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "fatal.h"
#include "security/Certificate.h"
#include "security/KeyData.h"
#include "SquidConfig.h"
#include "ssl/bio.h"
#include "ssl/gadgets.h"

/// load the traffic-signing certificate and the chain from certFile
bool
Security::KeyData::loadCertificates()
{
    debugs(83, DBG_IMPORTANT, "Using certificate in " << certFile);
    cert.reset(); // paranoid: ensure cert is unset

#if USE_OPENSSL
    const auto bundledCerts = Ssl::LoadCertificates(certFile.c_str());

    // selected bundled certificates in sending order: wireCerts = cert + chain
    CertList wireCerts;
    for (const auto &bundledCert: bundledCerts) {
        assert(bundledCert);

        // the very first bundled certificate is the required traffic-signing cert
        if (!cert) {
            cert = bundledCert;
            assert(wireCerts.empty());
            wireCerts.emplace_back(bundledCert);
            debugs(83, DBG_PARSE_NOTE(2), "Using traffic-signing certificate: " << *cert);
            continue;
        }

        assert(!wireCerts.empty());

        // We cannot chain any certificate after a self-signed certificate. This
        // check also protects the IssuedBy() check below from adding duplicated
        // (i.e. listed multiple times in the bundle) self-signed certificates.
        if (SelfSigned(*wireCerts.back())) {
            debugs(83, DBG_PARSE_NOTE(2), "WARNING: Ignoring certificate after a self-signed one: " << *bundledCert);
            continue; // ... but keep going to report all ignored certificates
        }

        // add the bundled certificate if it extends the chain further
        if (IssuedBy(*wireCerts.back(), *bundledCert)) {
            debugs(83, DBG_PARSE_NOTE(3), "Adding issuer CA: " << *bundledCert);
            // OpenSSL API requires that we order certificates such that the
            // chain can be appended directly into the on-wire traffic.
            chain.emplace_back(bundledCert);
            wireCerts.emplace_back(bundledCert);
            continue;
        }

        debugs(83, DBG_PARSE_NOTE(2), "WARNING: Ignoring certificate that does not extend the chain: " << *bundledCert);
    }

#elif USE_GNUTLS
    const char *certFilename = certFile.c_str();
    gnutls_datum_t data;
    Security::LibErrorCode x = gnutls_load_file(certFilename, &data);
    if (x != GNUTLS_E_SUCCESS) {
        // TODO: Convert the rest of this method to throw on errors instead.
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

    // XXX: implement chain loading
    debugs(83, 2, "Loading certificate chain from PEM files not implemented in this Squid.");

#else
    // do nothing.
#endif

    if (!cert) {
        debugs(83, DBG_IMPORTANT, "ERROR: unable to load certificate from '" << certFile << "'");
    }

    return bool(cert);
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

    try {
        if (!loadCertificates())
            throw TextException("missing traffic-signing certificate", Here());
    }
    catch (...) {
        // XXX: Reject malformed configurations by letting exceptions propagate.
        debugs(83, DBG_CRITICAL, "ERROR: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' cannot load certificate(s) from '" << certFile << "':" <<
               Debug::Extra << "problem: " << CurrentException);
    }

    // pkey is mandatory, not having it makes cert and chain pointless.
    if (!loadX509PrivateKeyFromFile()) {
        debugs(83, DBG_IMPORTANT, "WARNING: '" << portType << "_port " << port.s.toUrl(buf, sizeof(buf)) << "' missing private key in '" << privateKeyFile << "'");
        cert.reset();
        chain.clear();
    }
}

