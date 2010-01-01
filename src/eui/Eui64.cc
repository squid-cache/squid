/*
 * DEBUG: section ??	EUI-64 Handling
 * AUTHOR: Amos Jeffries
 *
 * Copyright (c) 2009, Amos Jeffries <squid3@treenet.co.nz>
 */

#include "config.h"

#if USE_SQUID_EUI

#include "Debug.h"
#include "eui/Eui64.h"
#include "globals.h"
#include "ip/IpAddress.h"

#if HAVE_SYS_EUI64_H
#include <sys/eui64.h>
#else
#include "eui64_aton.h"
#endif

bool
Eui::Eui64::decode(const char *asc)
{
    if (eui64_aton(asc, (struct eui64 *)eui) != 0) return false;

    return true;
}

bool
Eui::Eui64::encode(char *buf, const int len)
{
    if (len < SZ_EUI64_BUF) return false;

    snprintf(buf, len, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
             eui[0], eui[1], eui[2], eui[3],
             eui[4], eui[5], eui[6], eui[7]);
    return true;
}

// return binary representation of the EUI
bool
Eui::Eui64::lookup(IpAddress &c)
{
    /* try to short-circuit slow OS lookups by using SLAAC data */
    if (lookupSlaac(c)) return true;

    // find EUI-64 some other way. NDP table lookup?
    return lookupNdp(c);
}

bool
Eui::Eui64::lookupSlaac(IpAddress &c)
{
#if USE_IPV6
    /* RFC 4291 Link-Local unicast addresses which contain SLAAC - usually trustable. */
    if (c.IsSiteLocal6() && c.IsSlaac() ) {

        // strip the final 64 bits of the address...
        struct in6_addr tmp;
        c.GetInAddr(tmp);
        memcpy(eui, &(tmp.s6_addr[8]), SZ_EUI64_BUF);

        return true;
    }
#endif
    return false;
}

// return binary representation of the EUI
bool
Eui::Eui64::lookupNdp(IpAddress &c)
{
#if USE_IPV6

#if 0 /* no OS yet supported for NDP protocol lookup */

#else
    debugs(28, 0, "ERROR: ARP / MAC / EUI-* operations not supported on this operating system.");
#endif

    /*
     * Address was not found on any interface
     */
    debugs(28, 3, HERE << c << " NOT found");
#else
    debugs(28, 0, "ERROR: IPv6 EUI-64 operations not supported on this operating system.");
#endif

    clear();
    return false;
}

#endif /* USE_SQUID_EUI */
