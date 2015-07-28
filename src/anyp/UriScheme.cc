/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 23    URL Scheme parsing */

#include "squid.h"
#include "anyp/UriScheme.h"

char const *
AnyP::UriScheme::c_str() const
{
    if (theScheme_ == AnyP::PROTO_UNKNOWN)
        return "(unknown)";

    static char out[BUFSIZ];
    int p = 0;

    if (theScheme_ > AnyP::PROTO_NONE && theScheme_ < AnyP::PROTO_MAX) {
        const char *in = AnyP::ProtocolType_str[theScheme_];
        for (; p < (BUFSIZ-1) && in[p] != '\0'; ++p)
            out[p] = xtolower(in[p]);
    }
    out[p] = '\0';
    return out;
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

