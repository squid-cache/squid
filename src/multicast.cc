/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 07    Multicast */

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

    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1) < 0) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "mcastSetTtl: FD " << fd << ", TTL: " << mcast_ttl << ": " << xstrerr(xerrno));
    }
#endif

    return 0;
}

void
mcastJoinGroups(const ipcache_addrs *ia, const Dns::LookupDetails &, void *)
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
        if (setsockopt(icpIncomingConn->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1) < 0) {
            int xerrno = errno;
            debugs(7, DBG_IMPORTANT, "ERROR: " << icpIncomingConn << " can't disable multicast loopback: " << xstrerr(xerrno));
        }
    }

#endif
}

