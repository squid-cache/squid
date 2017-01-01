/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

