/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "dns/rfc1035.h"
#include "dns/rfc2671.h"

int
rfc2671RROptPack(char *buf, size_t sz, ssize_t edns_sz)
{
    // set the OPT record correctly. base it on a macro size of the Squid DNS read buffer
    static rfc1035_rr opt;

    // EDNS OPT record says only what our DNS buffer size is so far.
    snprintf(opt.name, RFC1035_MAXHOSTNAMESZ, ".");
    opt.type = RFC1035_TYPE_OPT;
    opt._class = min(edns_sz, (ssize_t)SQUID_UDP_SO_RCVBUF-1);
    opt.ttl = 0; // relevant?
    opt.rdata = NULL;
    opt.rdlength = 0;

    return rfc1035RRPack(buf, sz, &opt);
}

