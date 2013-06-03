/*
 * DEBUG: section 07    Multicast
 * AUTHOR: Martin Hamilton
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

#include "squid.h"
#include "comm/Connection.h"
#include "Debug.h"
// XXX: for icpIncomingConn - need to pass it as a generic parameter.
#include "ICP.h"
#include "ipcache.h"
#include "multicast.h"

int
mcastSetTtl(int fd, int mcast_ttl)
{
#ifdef IP_MULTICAST_TTL
    char ttl = (char) mcast_ttl;

    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1) < 0)
        debugs(50, DBG_IMPORTANT, "comm_set_mcast_ttl: FD " << fd << ", TTL: " << mcast_ttl << ": " << xstrerror());

#endif

    return 0;
}

void
mcastJoinGroups(const ipcache_addrs *ia, const DnsLookupDetails &, void *datanotused)
{
#ifdef IP_MULTICAST_TTL
    struct ip_mreq mr;
    int i;

    if (ia == NULL) {
        debugs(7, DBG_CRITICAL, "comm_join_mcast_groups: Unknown host");
        return;
    }

    for (i = 0; i < (int) ia->count; ++i) {
        debugs(7, 9, "Listening for ICP requests on " << ia->in_addrs[i] );

        if ( ! ia->in_addrs[i].isIPv4() ) {
            debugs(7, 9, "ERROR: IPv6 Multicast Listen has not been implemented!");
            continue;
        }

        ia->in_addrs[i].getInAddr(mr.imr_multiaddr);

        mr.imr_interface.s_addr = INADDR_ANY;

        if (setsockopt(icpIncomingConn->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &mr, sizeof(struct ip_mreq)) < 0)
            debugs(7, DBG_IMPORTANT, "ERROR: Join failed for " << icpIncomingConn << ", Multicast IP=" << ia->in_addrs[i]);

        char c = 0;
        if (setsockopt(icpIncomingConn->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1) < 0)
            debugs(7, DBG_IMPORTANT, "ERROR: " << icpIncomingConn << " can't disable multicast loopback: " << xstrerror());
    }

#endif
}
