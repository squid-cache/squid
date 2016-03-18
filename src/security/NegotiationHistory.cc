/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MemBuf.h"
#include "security/NegotiationHistory.h"
#include "SquidConfig.h"
#if USE_OPENSSL
#include "ssl/bio.h"
#include "ssl/support.h"
#endif

Security::NegotiationHistory::NegotiationHistory():
    helloVersion_(-1),
    supportedVersion_(-1),
    version_(-1)
#if USE_OPENSSL
    , cipher(NULL)
#endif
{
}

const char *
Security::NegotiationHistory::printTlsVersion(int v) const
{
#if USE_OPENSSL
    switch(v) {
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    case TLS1_2_VERSION:
        return "TLS/1.2";
    case TLS1_1_VERSION:
        return "TLS/1.1";
#endif
    case TLS1_VERSION:
        return "TLS/1.0";
    case SSL3_VERSION:
        return "SSL/3.0";
    case SSL2_VERSION:
        return "SSL/2.0";
    default:
        return nullptr;
    }
#else
    return nullptr;
#endif
}

void
Security::NegotiationHistory::fillWith(Security::SessionPtr ssl)
{
#if USE_OPENSSL
    if ((cipher = SSL_get_current_cipher(ssl)) != NULL) {
        // Set the negotiated version only if the cipher negotiated
        // else probably the negotiation is not completed and version
        // is not the final negotiated version
        version_ = ssl->version;
    }

    BIO *b = SSL_get_rbio(ssl);
    Ssl::Bio *bio = static_cast<Ssl::Bio *>(b->ptr);

    if (::Config.onoff.logTlsServerHelloDetails) {
        if (Ssl::ServerBio *srvBio = dynamic_cast<Ssl::ServerBio *>(bio))
            srvBio->extractHelloFeatures();
    }

    const Ssl::Bio::sslFeatures &features = bio->receivedHelloFeatures();
    helloVersion_ = features.sslHelloVersion;
    supportedVersion_ = features.sslVersion;

    debugs(83, 5, "SSL connection info on FD " << bio->fd() <<
           " SSL version " << version_ <<
           " negotiated cipher " << cipherName());
#endif
}

const char *
Security::NegotiationHistory::cipherName() const
{
#if USE_OPENSSL
    if (!cipher)
        return nullptr;

    return SSL_CIPHER_get_name(cipher);
#else
    return nullptr;
#endif
}

