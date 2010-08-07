/*
 * DEBUG: section 21    Misc Functions
 * AUTHOR: Amos Jeffries
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "config.h"
#include "Debug.h"
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
#if USE_IPV6
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
    close(s);

    debugs(3, 2, "IPv6 transport " << (EnableIpv6?"Enabled":"Disabled"));
#else
    debugs(3, 2, "IPv6 transport forced OFF by build parameters.");
    EnableIpv6 = IPV6_OFF;
#endif
}
