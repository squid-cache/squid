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

Security::NegotiationHistory::NegotiationHistory()
#if USE_OPENSSL
    : cipher(NULL)
#endif
{
}

const char *
Security::NegotiationHistory::printTlsVersion(AnyP::ProtocolVersion const &v) const
{
    if (v.protocol != AnyP::PROTO_SSL && v.protocol != AnyP::PROTO_TLS)
        return nullptr;

    static char buf[512];
    snprintf(buf, sizeof(buf), "%s/%d.%d", AnyP::ProtocolType_str[v.protocol], v.major, v.minor);
    return buf;
}

#if USE_OPENSSL
static AnyP::ProtocolVersion
toProtocolVersion(const int v)
{
    switch(v) {
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    case TLS1_2_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 2);
    case TLS1_1_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 1);
#endif
    case TLS1_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 0);
    case SSL3_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_SSL, 3, 0);
    case SSL2_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_SSL, 2, 0);
    default:
        return AnyP::ProtocolVersion();
    }
}
#endif

void
Security::NegotiationHistory::retrieveNegotiatedInfo(Security::SessionPtr ssl)
{
#if USE_OPENSSL
    if ((cipher = SSL_get_current_cipher(ssl)) != NULL) {
        // Set the negotiated version only if the cipher negotiated
        // else probably the negotiation is not completed and version
        // is not the final negotiated version
        version_ = toProtocolVersion(ssl->version);
    }

    if (do_debug(83, 5)) {
        BIO *b = SSL_get_rbio(ssl);
        Ssl::Bio *bio = static_cast<Ssl::Bio *>(b->ptr);
        debugs(83, 5, "SSL connection info on FD " << bio->fd() <<
               " SSL version " << version_ <<
               " negotiated cipher " << cipherName());
    }
#endif
}

void
Security::NegotiationHistory::retrieveParsedInfo(Security::TlsDetails::Pointer const &details)
{
    if (details) {
        helloVersion_ = details->tlsVersion;
        supportedVersion_ = details->tlsSupportedVersion;
    }
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

