/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 23    URL Scheme parsing */

#include "squid.h"
#include "anyp/UriScheme.h"

AnyP::UriScheme::LowercaseSchemeNames AnyP::UriScheme::LowercaseSchemeNames_;

AnyP::UriScheme::UriScheme(AnyP::ProtocolType const aScheme, const char *img) :
    theScheme_(aScheme)
{
    // RFC 3986 section 3.1: schemes are case-insensitive.

    // To improve diagnostic, remember exactly how an unsupported scheme looks like.
    // XXX: Object users may rely on toLower() canonicalization that we refuse to provide.
    if (img && theScheme_ == AnyP::PROTO_UNKNOWN)
        image_ = img;

    // XXX: A broken caller supplies an image of an absent scheme?
    // XXX: We assume that the caller is using a lower-case image.
    else if (img && theScheme_ == AnyP::PROTO_NONE)
        image_ = img;

    else if (theScheme_ > AnyP::PROTO_NONE && theScheme_ < AnyP::PROTO_MAX)
        image_ = LowercaseSchemeNames_.at(theScheme_);
    // else, the image remains empty (e.g., "://example.com/")
    // hopefully, theScheme_ is PROTO_NONE here
}

void
AnyP::UriScheme::Init()
{
    if (LowercaseSchemeNames_.empty()) {
        LowercaseSchemeNames_.reserve(sizeof(SBuf) * AnyP::PROTO_MAX);
        // TODO: use base/EnumIterator.h if possible
        for (int i = AnyP::PROTO_NONE; i < AnyP::PROTO_MAX; ++i) {
            SBuf image(ProtocolType_str[i]);
            image.toLower();
            LowercaseSchemeNames_.emplace_back(image);
        }
    }
}

unsigned short
AnyP::UriScheme::defaultPort() const
{
    switch (theScheme_) {

    case AnyP::PROTO_HTTP:
        return 80;

    case AnyP::PROTO_HTTPS:
        return 443;

    case AnyP::PROTO_FTP:
        return 21;

    case AnyP::PROTO_COAP:
    case AnyP::PROTO_COAPS:
        // coaps:// default is TBA as of draft-ietf-core-coap-08.
        // Assuming IANA policy of allocating same port for base and TLS protocol versions will occur.
        return 5683;

    case AnyP::PROTO_GOPHER:
        return 70;

    case AnyP::PROTO_WAIS:
        return 210;

    case AnyP::PROTO_CACHE_OBJECT:
        return CACHE_HTTP_PORT;

    case AnyP::PROTO_WHOIS:
        return 43;

    default:
        return 0;
    }
}

