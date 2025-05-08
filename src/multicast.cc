/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 07    Multicast */

#include "squid.h"
#include "comm/Connection.h"
#include "comm/Tcp.h"
#include "debug/Stream.h"
// XXX: for icpIncomingConn - need to pass it as a generic parameter.
#include "ICP.h"
#include "ipcache.h"
#include "multicast.h"
#include "sbuf/Stream.h"

int
mcastSetTtl(int fd, int mcast_ttl)
{
#if defined(IP_MULTICAST_TTL)
    auto ttl = char(mcast_ttl);
    Comm::SetSocketOption(fd, IPPROTO_IP, IP_MULTICAST_TTL, ttl, ToSBuf("IP_MULTICAST_TTL to ", mcast_ttl, " hops"));
#endif
    return 0;
}

void
mcastJoinGroups(const ipcache_addrs *ia, const Dns::LookupDetails &, void *)
{
#ifdef IP_MULTICAST_TTL
    struct ip_mreq mr;

    if (ia == nullptr) {
        debugs(7, DBG_CRITICAL, "ERROR: comm_join_mcast_groups: Unknown host");
        return;
    }

    for (const auto &ip: ia->goodAndBad()) { // TODO: Consider using just good().
        debugs(7, 9, "Listening for ICP requests on " << ip);

        if (!ip.isIPv4()) {
            debugs(7, 9, "ERROR: IPv6 Multicast Listen has not been implemented!");
            continue;
        }

        ip.getInAddr(mr.imr_multiaddr);

        mr.imr_interface.s_addr = INADDR_ANY;

        Comm::SetSocketOption(icpIncomingConn->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, mr,
                              ToSBuf("IP_ADD_MEMBERSHIP for multicast-IP=", ip, " on ICP listener ", icpIncomingConn));

        Comm::SetBooleanSocketOption(icpIncomingConn->fd, IPPROTO_IP, IP_MULTICAST_LOOP, false,
                                     ToSBuf("IP_MULTICAST_LOOP on ICP listener ", icpIncomingConn));
    }

#endif
}

