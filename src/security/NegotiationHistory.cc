/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
    : cipher(nullptr)
#endif
{
}

const char *
Security::NegotiationHistory::printTlsVersion(AnyP::ProtocolVersion const &v) const
{
    if (!TlsFamilyProtocol(v))
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
#if defined(TLS1_3_VERSION)
    case TLS1_3_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 3);
#endif
#if defined(TLS1_2_VERSION)
    case TLS1_2_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 2);
#endif
#if defined(TLS1_1_VERSION)
    case TLS1_1_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 1);
#endif
#if defined(TLS1_VERSION)
    case TLS1_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_TLS, 1, 0);
#endif
#if defined(SSL3_VERSION)
    case SSL3_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_SSL, 3, 0);
#endif
#if defined(SSL2_VERSION)
    case SSL2_VERSION:
        return AnyP::ProtocolVersion(AnyP::PROTO_SSL, 2, 0);
#endif
    default:
        return AnyP::ProtocolVersion();
    }
}
#endif

void
Security::NegotiationHistory::retrieveNegotiatedInfo(const Security::SessionPointer &session)
{
#if USE_OPENSSL
    if ((cipher = SSL_get_current_cipher(session.get()))) {
        // Set the negotiated version only if the cipher negotiated
        // else probably the negotiation is not completed and version
        // is not the final negotiated version
        version_ = toProtocolVersion(SSL_version(session.get()));
    }

    if (Debug::Enabled(83, 5)) {
        BIO *b = SSL_get_rbio(session.get());
        Ssl::Bio *bio = static_cast<Ssl::Bio *>(BIO_get_data(b));
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

