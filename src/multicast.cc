
/*
 * $Id: multicast.cc,v 1.11 2003/02/21 22:50:10 robertc Exp $
 *
 * DEBUG: section 7     Multicast
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

int
mcastSetTtl(int fd, int mcast_ttl)
{
#ifdef IP_MULTICAST_TTL
    char ttl = (char) mcast_ttl;

    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1) < 0)
        debug(50, 1) ("comm_set_mcast_ttl: FD %d, TTL: %d: %s\n",
                      fd, mcast_ttl, xstrerror());

#endif

    return 0;
}

void
mcastJoinGroups(const ipcache_addrs * ia, void *datanotused)
{
#ifdef IP_MULTICAST_TTL
    int fd = theInIcpConnection;

    struct ip_mreq mr;
    int i;
    int x;
    char c = 0;

    if (ia == NULL) {
        debug(7, 0) ("comm_join_mcast_groups: Unknown host\n");
        return;
    }

    for (i = 0; i < (int) ia->count; i++) {
        debug(7, 10) ("Listening for ICP requests on %s\n",
                      inet_ntoa(*(ia->in_addrs + i)));
        mr.imr_multiaddr.s_addr = (ia->in_addrs + i)->s_addr;
        mr.imr_interface.s_addr = INADDR_ANY;
        x = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,

                       (char *) &mr, sizeof(struct ip_mreq));

        if (x < 0)
            debug(7, 1) ("comm_join_mcast_groups: FD %d, [%s]\n",
                         fd, inet_ntoa(*(ia->in_addrs + i)));

        x = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1);

        if (x < 0)
            debug(7, 1) ("Can't disable multicast loopback: %s\n", xstrerror());
    }

#endif
}
