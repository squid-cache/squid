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
#ifdef HAVE_NET_PF_PFVAR_H
#include <net/pf/pfvar.h>
#endif /* HAVE_NET_PF_PFVAR_H */
#ifdef HAVE_NET_PFVAR_H
#include <net/pfvar.h>
#endif /* HAVE_NET_PFVAR_H */
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
IpIntercept::NetfilterInterception(int fd, const IpAddress &me, IpAddress &dst, int silent)
{
#if LINUX_NETFILTER
    struct addrinfo *lookup = NULL;

    dst.GetAddrInfo(lookup,AF_INET);

    /** \par
     * Try NAT lookup for REDIRECT or DNAT targets. */
    if ( getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST, lookup->ai_addr, &lookup->ai_addrlen) != 0) {
        if (!silent) {
            debugs(89, DBG_IMPORTANT, HERE << " NF getsockopt(SO_ORIGINAL_DST) failed on FD " << fd << ": " << xstrerror());
            last_reported = squid_curtime;
        }
    } else {
        dst = *lookup;
    }

    dst.FreeAddrInfo(lookup);

    if (me != dst) {
        debugs(89, 5, HERE << "address NAT: me= " << me << ", dst= " << dst);
        return 0;
    }

    debugs(89, 9, HERE << "address: me= " << me << ", dst= " << dst);
#endif
    return -1;
}

int
IpIntercept::NetfilterTransparent(int fd, const IpAddress &me, IpAddress &client, int silent)
{
#if LINUX_NETFILTER

    /* Trust the user configured properly. If not no harm done.
     * We will simply attempt a bind outgoing on our own IP.
     */
    if (fd_table[fd].flags.transparent) {
        client.SetPort(0); // allow random outgoing port to prevent address clashes
        debugs(89, 5, HERE << "address TPROXY: me= " << me << ", client= " << client);
        return 0;
    }

    debugs(89, 9, HERE << "address: me= " << me << ", client= " << client);
#endif
    return -1;
}

int
IpIntercept::IpfwInterception(int fd, const IpAddress &me, IpAddress &dst, int silent)
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
        debugs(89, 5, HERE << "address NAT: me= " << me << ", dst= " << dst);
        return 0;
    }

    debugs(89, 9, HERE << "address: me= " << me << ", dst= " << dst);
#endif
    return -1;
}

int
IpIntercept::IpfInterception(int fd, const IpAddress &me, IpAddress &client, IpAddress &dst, int silent)
{
#if IPF_TRANSPARENT  /* --enable-ipf-transparent */

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
    natLookup.nl_outport = htons(dst.GetPort());
    me.GetInAddr(natLookup.nl_inip);
    dst.GetInAddr(natLookup.nl_outip);
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
        if (!silent) {
            debugs(89, DBG_IMPORTANT, HERE << "NAT open failed: " << xstrerror());
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
            if (!silent) {
                debugs(89, DBG_IMPORTANT, HERE << "NAT lookup failed: ioctl(SIOCGNATL)");
                last_reported = squid_curtime;
            }

            close(natfd);
            natfd = -1;
        }

        return -1;
    } else {
        if (client != natLookup.nl_realip) {
            client = natLookup.nl_realip;
            client.SetPort(ntohs(natLookup.nl_realport));
        }
        // else. we already copied it.

        debugs(89, 5, HERE << "address NAT: me= " << me << ", client= " << client << ", dst= " << dst);
        return 0;
    }

    debugs(89, 9, HERE << "address: me= " << me << ", client= " << client << ", dst= " << dst);

#endif /* --enable-ipf-transparent */
    return -1;
}

int
IpIntercept::PfInterception(int fd, const IpAddress &me, IpAddress &client, IpAddress &dst, int silent)
{
#if PF_TRANSPARENT  /* --enable-pf-transparent */

    struct pfioc_natlook nl;
    static int pffd = -1;

    if (pffd < 0)
        pffd = open("/dev/pf", O_RDONLY);

    if (pffd < 0) {
        if (!silent) {
            debugs(89, DBG_IMPORTANT, HERE << "PF open failed: " << xstrerror());
            last_reported = squid_curtime;
        }
        return -1;
    }

    memset(&nl, 0, sizeof(struct pfioc_natlook));
    dst.GetInAddr(nl.saddr.v4);
    nl.sport = htons(dst.GetPort());

    me.GetInAddr(nl.daddr.v4);
    nl.dport = htons(me.GetPort());

    nl.af = AF_INET;
    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;

    if (ioctl(pffd, DIOCNATLOOK, &nl)) {
        if (errno != ENOENT) {
            if (!silent) {
                debugs(89, DBG_IMPORTANT, HERE << "PF lookup failed: ioctl(DIOCNATLOOK)");
                last_reported = squid_curtime;
            }
            close(pffd);
            pffd = -1;
        }
    } else {
        int natted = (client != nl.rdaddr.v4);
        client = nl.rdaddr.v4;
        client.SetPort(ntohs(nl.rdport));

        if (natted) {
            debugs(89, 5, HERE << "address NAT: me= " << me << ", client= " << client << ", dst= " << dst);
            return 0;
        }
    }

    debugs(89, 9, HERE << "address: me= " << me << ", client= " << client << ", dst= " << dst);

#endif /* --enable-pf-transparent */
    return -1;
}


int
IpIntercept::NatLookup(int fd, const IpAddress &me, const IpAddress &peer, IpAddress &client, IpAddress &dst)
{
    /* --enable-linux-netfilter    */
    /* --enable-ipfw-transparent   */
    /* --enable-ipf-transparent    */
    /* --enable-pf-transparent     */
#if IPF_TRANSPARENT || LINUX_NETFILTER || IPFW_TRANSPARENT || PF_TRANSPARENT

    client = me;
    dst = peer;

#if 0
    // Crop interception errors down to one per minute.
    int silent = (squid_curtime - last_reported > 60 ? 0 : 1);
#else
    // Show all interception errors.
    int silent = 0;
#endif

    debugs(89, 5, HERE << "address BEGIN: me= " << me << ", client= " << client <<
           ", dst= " << dst << ", peer= " << peer);

    /* NP: try TPROXY first, its much quieter than NAT when non-matching */
    if (transparent_active) {
        if ( NetfilterTransparent(fd, me, dst, silent) == 0) return 0;
    }

    /* NAT is only available in IPv4 */
    if ( !me.IsIPv4()   ) return -1;
    if ( !peer.IsIPv4() ) return -1;

    if (intercept_active) {
        /* NAT methods that use sock-opts to return client address */
        if ( NetfilterInterception(fd, me, client, silent) == 0) return 0;
        if ( IpfwInterception(fd, me, client, silent) == 0) return 0;

        /* NAT methods that use ioctl to return client address AND destination address */
        if ( PfInterception(fd, me, client, dst, silent) == 0) return 0;
        if ( IpfInterception(fd, me, client, dst, silent) == 0) return 0;
    }

#else /* none of the transparent options configured */
    debugs(89, DBG_IMPORTANT, "WARNING: transparent proxying not supported");
#endif

    return -1;
}

#if LINUX_TPROXY2
int
IpIntercept::SetTproxy2OutgoingAddr(int fd, const IpAddress &src)
{
    IpAddress addr;
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

bool
IpIntercept::ProbeForTproxy(IpAddress &test)
{
    debugs(3, 3, "Detect TPROXY support on port " << test);
#if LINUX_TPROXY2

    if (Ip::EnableIpv6) {
        /* TPROXYv2 is not IPv6 capable. Force wildcard sockets to IPv4. Die on IPv6 IPs */
        debugs(3, DBG_IMPORTANT, "Disabling IPv6 on port " << test << " (TPROXYv2 interception enabled)");
        if ( test.IsIPv6() && !test.SetIPv4() ) {
            debugs(3, DBG_CRITICAL, "IPv6 requires TPROXYv4 support. You only have TPROXYv2 for " << test );
            return false;
        }
    }
    return true;

#else /* not LINUX_TPROXY2 */

#if defined(IP_TRANSPARENT)

    int tos = 1;
    int tmp_sock = -1;

    /* Probe to see if the Kernel TPROXY support is IPv6-enabled */
    if (test.IsIPv6()) {
        debugs(3, 3, "...Probing for IPv6 TPROXY support.");

        struct sockaddr_in6 tmp_ip6;
        IpAddress tmp = "::2";
        tmp.SetPort(0);
        tmp.GetSockAddr(tmp_ip6);

        if ( (tmp_sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)) >= 0 &&
                setsockopt(tmp_sock, SOL_IP, IP_TRANSPARENT, (char *)&tos, sizeof(int)) == 0 &&
                bind(tmp_sock, (struct sockaddr*)&tmp_ip6, sizeof(struct sockaddr_in6)) == 0 ) {

            debugs(3, 3, "IPv6 TPROXY support detected. Using.");
            close(tmp_sock);
            return true;
        }
        if (tmp_sock >= 0) {
            close(tmp_sock);
            tmp_sock = -1;
        }
    }

    if ( test.IsIPv6() && !test.SetIPv4() ) {
        debugs(3, DBG_CRITICAL, "TPROXY lacks IPv6 support for " << test );
        return false;
    }

    /* Probe to see if the Kernel TPROXY support is IPv4-enabled (aka present) */
    if (test.IsIPv4()) {
        debugs(3, 3, "...Probing for IPv4 TPROXY support.");

        struct sockaddr_in tmp_ip4;
        IpAddress tmp = "127.0.0.2";
        tmp.SetPort(0);
        tmp.GetSockAddr(tmp_ip4);

        if ( (tmp_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) >= 0 &&
                setsockopt(tmp_sock, SOL_IP, IP_TRANSPARENT, (char *)&tos, sizeof(int)) == 0 &&
                bind(tmp_sock, (struct sockaddr*)&tmp_ip4, sizeof(struct sockaddr_in)) == 0 ) {

            debugs(3, 3, "IPv4 TPROXY support detected. Using.");
            close(tmp_sock);
            return true;
        }
        if (tmp_sock >= 0) {
            close(tmp_sock);
        }
    }

#else /* undefined IP_TRANSPARENT */
    debugs(3, 3, "setsockopt(IP_TRANSPARENT) not supported on this platform. Disabling TPROXYv4.");
#endif
#endif /* LINUX_TPROXY2 */
    return false;
}
