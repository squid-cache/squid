/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Misc Functions */

#include "squid.h"
#include "Debug.h"
#include "ip/Address.h"
#include "ip/tools.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

int Ip::EnableIpv6 = IPV6_OFF;

void
Ip::ProbeTransport()
{
    // check for usable IPv6 sockets
    int s = socket(PF_INET6, SOCK_STREAM, 0);
    if (s < 0) {
        debugs(3, 2, "IPv6 not supported on this machine. Auto-Disabled.");
        EnableIpv6 = IPV6_OFF;
        return;
    }

    // Test for v4-mapping capability
    // (AKA. the operating system supports RFC 3493 section 5.3)
#if defined(IPV6_V6ONLY)
    int tos = 0;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &tos, sizeof(int)) == 0) {
        debugs(3, 2, "Detected IPv6 hybrid or v4-mapping stack...");
        EnableIpv6 |= IPV6_SPECIAL_V4MAPPING;
    } else {
        debugs(3, 2, "Detected split IPv4 and IPv6 stacks ...");
        EnableIpv6 |= IPV6_SPECIAL_SPLITSTACK;
    }
#else
    // compliance here means they at least supply the option for compilers building code
    // even if possibly to return hard-coded -1 on use.
    debugs(3, 2, "Missing RFC 3493 compliance - attempting split IPv4 and IPv6 stacks ...");
    EnableIpv6 |= IPV6_SPECIAL_SPLITSTACK;
#endif

    // Test for IPv6 loopback/localhost address binding
    Ip::Address ip;
    ip.setLocalhost();
    if (ip.isIPv6()) { // paranoid; always succeeds if we got this far
        struct sockaddr_in6 sin;
        ip.getSockAddr(sin);
        if (bind(s, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin)) != 0) {
            debugs(3, DBG_CRITICAL, "WARNING: BCP 177 violation. Detected non-functional IPv6 loopback.");
            EnableIpv6 = IPV6_OFF;
        } else {
            debugs(3, 2, "Detected functional IPv6 loopback ...");
        }
    }

    close(s);

#if USE_IPV6
    debugs(3, 2, "IPv6 transport " << (EnableIpv6?"Enabled":"Disabled"));
#else
    debugs(3, 2, "IPv6 transport " << (EnableIpv6?"Available":"Disabled"));
    if (EnableIpv6 != IPV6_OFF) {
        debugs(3, DBG_CRITICAL, "WARNING: BCP 177 violation. IPv6 transport forced OFF by build parameters.");
        EnableIpv6 = IPV6_OFF;
    }
#endif
}

