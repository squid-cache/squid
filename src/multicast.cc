
/*
 * $Id: multicast.cc,v 1.2 1997/06/26 22:35:54 wessels Exp $
 *
 * DEBUG: section 5     Socket Functions
 * AUTHOR: Martin Hamilton
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
mcastJoinGroups(const ipcache_addrs * ia, void *data)
{
#ifdef IP_MULTICAST_TTL
    int fd = theInIcpConnection;
    struct ip_mreq mr;
    int i;
    int x;
    char c = 0;
    if (ia == NULL) {
	debug(5, 0) ("comm_join_mcast_groups: Unknown host\n");
	return;
    }
    for (i = 0; i < (int) ia->count; i++) {
	debug(5, 10) ("Listening for ICP requests on %s\n",
	    inet_ntoa(*(ia->in_addrs + i)));
	mr.imr_multiaddr.s_addr = (ia->in_addrs + i)->s_addr;
	mr.imr_interface.s_addr = INADDR_ANY;
	x = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	    (char *) &mr, sizeof(struct ip_mreq));
	if (x < 0)
	    debug(5, 1) ("comm_join_mcast_groups: FD %d, [%s]\n",
		fd, inet_ntoa(*(ia->in_addrs + i)));
	x = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1);
	if (x < 0)
	    debug(5, 1) ("Can't disable multicast loopback: %s\n", xstrerror());
    }
#endif
}

void
mcastJoinVizSock(void)
{
#if defined(IP_ADD_MEMBERSHIP) && defined(IP_MULTICAST_TTL)
    int x;
    if (Config.vizHack.addr.s_addr > inet_addr("224.0.0.0")) {
	struct ip_mreq mr;
	char ttl = (char) Config.vizHack.mcast_ttl;
	memset(&mr, '\0', sizeof(struct ip_mreq));
	mr.imr_multiaddr.s_addr = Config.vizHack.addr.s_addr;
	mr.imr_interface.s_addr = INADDR_ANY;
	x = setsockopt(vizSock,
	    IPPROTO_IP,
	    IP_ADD_MEMBERSHIP,
	    (char *) &mr,
	    sizeof(struct ip_mreq));
	if (x < 0)
	    debug(50, 1) ("IP_ADD_MEMBERSHIP: FD %d, addr %s: %s\n",
		vizSock, inet_ntoa(Config.vizHack.addr), xstrerror());
	x = setsockopt(vizSock,
	    IPPROTO_IP,
	    IP_MULTICAST_TTL,
	    &ttl,
	    sizeof(char));
	if (x < 0)
	    debug(50, 1) ("IP_MULTICAST_TTL: FD %d, TTL %d: %s\n",
		vizSock, Config.vizHack.mcast_ttl, xstrerror());
	ttl = 0;
	x = sizeof(char);
	getsockopt(vizSock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, &x);
	debug(1, 0) ("vizSock on FD %d, ttl=%d\n", vizSock, (int) ttl);
    }
#else
    debug(1, 0) ("vizSock: Could not join multicast group\n");
#endif
}
