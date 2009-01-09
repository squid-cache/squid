/*
 * DEBUG: section 89    NAT / IP Interception
 * AUTHOR: Robert Collins
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
#include "IpIntercept.h"
#include "fde.h"

#if IPF_TRANSPARENT

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_IPL_H
#include <ipl.h>
#elif HAVE_NETINET_IPL_H
#include <netinet/ipl.h>
#endif
#if HAVE_IP_FIL_COMPAT_H
#include <ip_fil_compat.h>
#elif HAVE_NETINET_IP_FIL_COMPAT_H
#include <netinet/ip_fil_compat.h>
#elif HAVE_IP_COMPAT_H
#include <ip_compat.h>
#elif HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#if HAVE_IP_FIL_H
#include <ip_fil.h>
#elif HAVE_NETINET_IP_FIL_H
#include <netinet/ip_fil.h>
#endif
#if HAVE_IP_NAT_H
#include <ip_nat.h>
#elif HAVE_NETINET_IP_NAT_H
#include <netinet/ip_nat.h>
#endif

#endif /* IPF_TRANSPARENT required headers */

#if PF_TRANSPARENT
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#endif /* PF_TRANSPARENT required headers */

#if LINUX_NETFILTER
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#endif

#if LINUX_TPROXY2
#ifdef HAVE_LINUX_NETFILTER_IPV4_IP_TPROXY_H
#include <linux/netfilter_ipv4/ip_tproxy.h>
#else
#error " TPROXY v2 Header file missing: linux/netfilter_ipv4/ip_tproxy.h. Perhapse you meant to use TPROXY v4 ? "
#endif
#endif


// single global instance for access by other components.
IpIntercept IpInterceptor;

void
IpIntercept::StopTransparency(const char *str)
{
    if (transparent_active) {
        debugs(89, DBG_IMPORTANT, "Stopping full transparency: " << str);
        transparent_active = 0;
    }
}

void
IpIntercept::StopInterception(const char *str)
{
    if (intercept_active) {
        debugs(89, DBG_IMPORTANT, "Stopping IP interception: " << str);
        intercept_active = 0;
    }
}

int
IpIntercept::NetfilterInterception(int fd, const IPAddress &me, IPAddress &dst, int silent)
{
#if LINUX_NETFILTER
    struct addrinfo *lookup = NULL;

    dst.GetAddrInfo(lookup,AF_INET);

    /** \par
     * Try NAT lookup for REDIRECT or DNAT targets. */
    if ( getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, lookup->ai_addr, &lookup->ai_addrlen) == 0) {
        if (!silent) {
            debugs(89, DBG_IMPORTANT, HERE << " NF getsockopt(SO_ORIGINAL_DST) failed on FD " << fd << ": " << xstrerror());
            last_reported = squid_curtime;
        }
    } else {
        dst = *lookup;
    }

    dst.FreeAddrInfo(lookup);

    if (me != dst) {
        debugs(89, 5, HERE << "address: " << dst);
        return 0;
    }

    debugs(89, 9, HERE << "address: me= " << me << ", dst= " << dst);
#endif
    return -1;
}

int
IpIntercept::NetfilterTransparent(int fd, const IPAddress &me, IPAddress &client, int silent)
{
#if LINUX_NETFILTER

    /* Trust the user configured properly. If not no harm done.
     * We will simply attempt a bind outgoing on our own IP.
     */
    if (fd_table[fd].flags.transparent) {
        client.SetPort(0); // allow random outgoing port to prevent address clashes
        return 0;
    }
#endif
    return -1;
}

int
IpIntercept::IpfwInterception(int fd, const IPAddress &me, IPAddress &dst, int silent)
{
#if IPFW_TRANSPARENT
    struct addrinfo *lookup = NULL;

    dst.GetAddrInfo(lookup,AF_INET);

    /** \par
     * Try lookup for IPFW interception. */
    if ( getsockname(fd, lookup->ai_addr, &lookup->ai_addrlen) != 0 ) {
        if ( !silent ) {
            debugs(89, DBG_IMPORTANT, HERE << " IPFW getsockname(...) failed: " << xstrerror());
            last_reported = squid_curtime;
        }
    } else {
        dst = *lookup;
    }

    dst.FreeAddrInfo(lookup);

    if (me != dst) {
        debugs(89, 5, HERE << "address: " << dst);
        return 0;
    }

    debugs(89, 9, HERE << "address: me= " << me << ", dst= " << dst);
#endif
    return -1;
}

int
IpIntercept::NatLookup(int fd, const IPAddress &me, const IPAddress &peer, IPAddress &client, IPAddress &dst)
{
#if IPF_TRANSPARENT  /* --enable-ipf-transparent */
    client = me;
    if ( !me.IsIPv4() ) return -1;
    if ( !peer.IsIPv4() ) return -1;

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)

    struct ipfobj obj;
#else

    static int siocgnatl_cmd = SIOCGNATL & 0xff;

#endif

    struct natlookup natLookup;
    static int natfd = -1;
    int x;

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)

    obj.ipfo_rev = IPFILTER_VERSION;
    obj.ipfo_size = sizeof(natLookup);
    obj.ipfo_ptr = &natLookup;
    obj.ipfo_type = IPFOBJ_NATLOOKUP;
    obj.ipfo_offset = 0;
#endif

    natLookup.nl_inport = htons(me.GetPort());
    natLookup.nl_outport = htons(peer.GetPort());
    me.GetInAddr(natLookup.nl_inip);
    peer.GetInAddr(natLookup.nl_outip);
    natLookup.nl_flags = IPN_TCP;

    if (natfd < 0) {
        int save_errno;
        enter_suid();
#ifdef IPNAT_NAME

        natfd = open(IPNAT_NAME, O_RDONLY, 0);
#else

        natfd = open(IPL_NAT, O_RDONLY, 0);
#endif

        save_errno = errno;
        leave_suid();
        errno = save_errno;
    }

    if (natfd < 0) {
        if (squid_curtime - last_reported > 60) {
            debugs(89, 1, "clientNatLookup: NAT open failed: " << xstrerror());
            last_reported = squid_curtime;
            return -1;
        }
    }

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
    x = ioctl(natfd, SIOCGNATL, &obj);

#else
    /*
    * IP-Filter changed the type for SIOCGNATL between
    * 3.3 and 3.4.  It also changed the cmd value for
    * SIOCGNATL, so at least we can detect it.  We could
    * put something in configure and use ifdefs here, but
    * this seems simpler.
    */
    if (63 == siocgnatl_cmd) {

        struct natlookup *nlp = &natLookup;
        x = ioctl(natfd, SIOCGNATL, &nlp);
    } else {
        x = ioctl(natfd, SIOCGNATL, &natLookup);
    }

#endif
    if (x < 0) {
        if (errno != ESRCH) {
            if (squid_curtime - last_reported > 60) {
                debugs(89, 1, "clientNatLookup: NAT lookup failed: ioctl(SIOCGNATL)");
                last_reported = squid_curtime;
            }

            close(natfd);
            natfd = -1;
        }

        return -1;
    } else {
        if (me != natLookup.nl_realip) {
            client = natLookup.nl_realip;

            client.SetPort(ntohs(natLookup.nl_realport));
        }
        // else. we already copied it.

        return 0;
    }



#elif LINUX_NETFILTER || IPFW_TRANSPARENT /* --enable-linux-netfilter OR --enable-ipfw-transparent */

    /* Netfilter and IPFW share almost identical lookup methods for their NAT tables.
     * This allows us to perform a nice clean failover sequence for them.
     */

    client = me;
    dst = peer;

    if ( !me.IsIPv4()   ) return -1;
    if ( !peer.IsIPv4() ) return -1;

#if 0
    // Crop interception errors down to one per minute.
    int silent = (squid_curtime - last_reported > 60 ? 0 : 1);
#else
    // Show all interception errors.
    int silent = 0;
#endif

    if (intercept_active) {
        if ( NetfilterInterception(fd, me, client, silent) == 0) return 0;
        if ( IpfwInterception(fd, me, client, silent) == 0) return 0;
    }
    if (transparent_active) {
        if ( NetfilterTransparent(fd, me, dst, silent) == 0) return 0;
    }

    return -1;

#elif PF_TRANSPARENT  /* --enable-pf-transparent */

    struct pfioc_natlook nl;
    static int pffd = -1;

    if ( !me.IsIPv4() ) return -1;
    if ( !peer.IsIPv4() ) return -1;

    if (pffd < 0)
        pffd = open("/dev/pf", O_RDONLY);

    if (pffd < 0) {
        if (squid_curtime - last_reported > 60) {
            debugs(89, 1, "clientNatLookup: PF open failed: " << xstrerror());
            last_reported = squid_curtime;
        }

        return -1;

    }

    client.SetEmpty();

    memset(&nl, 0, sizeof(struct pfioc_natlook));
    peer.GetInAddr(nl.saddr.v4);
    nl.sport = htons(peer.GetPort());

    me.GetInAddr(nl.daddr.v4);
    nl.dport = htons(me.GetPort());

    nl.af = AF_INET;
    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;

    if (ioctl(pffd, DIOCNATLOOK, &nl)) {
        if (errno != ENOENT) {
            if (squid_curtime - last_reported > 60) {
                debugs(89, 1, "clientNatLookup: PF lookup failed: ioctl(DIOCNATLOOK)");
                last_reported = squid_curtime;
            }

            close(pffd);
            pffd = -1;
        }

        return -1;
    } else {
        int natted = (me != nl.rdaddr.v4);
        client = nl.rdaddr.v4;
        client.SetPort(ntohs(nl.rdport));

        if (natted)
            return 0;
        else
            return -1;
    }


#else /* none of the transparent options configured */

    debugs(89, 1, "WARNING: transparent proxying not supported");
    return -1;

#endif

}

#if LINUX_TPROXY2
IpIntercept::SetTproxy2OutgoingAddr(int fd, const IPAddress &src)
{
    IPAddress addr;
    struct in_tproxy itp;

    src.GetInAddr(itp.v.addr.faddr);
    itp.v.addr.fport = 0;

    /* If these syscalls fail then we just fallback to connecting
     * normally by simply ignoring the errors...
     */
    itp.op = TPROXY_ASSIGN;

    addr = (struct in_addr)itp.v.addr.faddr;
    addr.SetPort(itp.v.addr.fport);

    if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp, sizeof(itp)) == -1) {
        debugs(20, 1, "tproxy ip=" << addr << " ERROR ASSIGN");
        return -1;
    } else {
        itp.op = TPROXY_FLAGS;
        itp.v.flags = ITP_CONNECT;

        if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp, sizeof(itp)) == -1) {
            debugs(20, 1, "tproxy ip=" << addr << " ERROR CONNECT");
            return -1;
        }
    }

    return 0;
}
#endif
