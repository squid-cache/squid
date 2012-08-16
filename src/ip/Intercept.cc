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
#include "squid.h"
#include "comm/Connection.h"
#include "ip/Intercept.h"
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
#if HAVE_IPL_H
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
#if HAVE_ERRNO_H
#include <errno.h>
#endif

#endif /* IPF_TRANSPARENT required headers */

#if PF_TRANSPARENT
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#if HAVE_NET_PF_PFVAR_H
#include <net/pf/pfvar.h>
#endif /* HAVE_NET_PF_PFVAR_H */
#if HAVE_NET_PFVAR_H
#include <net/pfvar.h>
#endif /* HAVE_NET_PFVAR_H */
#endif /* PF_TRANSPARENT required headers */

#if LINUX_NETFILTER
#if HAVE_LIMITS_H
/* must be before including netfilter_ipv4.h */
#include <limits.h>
#endif
#include <linux/netfilter_ipv4.h>
#endif /* LINUX_NETFILTER required headers */

// single global instance for access by other components.
Ip::Intercept Ip::Interceptor;

void
Ip::Intercept::StopTransparency(const char *str)
{
    if (transparentActive_) {
        debugs(89, DBG_IMPORTANT, "Stopping full transparency: " << str);
        transparentActive_ = 0;
    }
}

void
Ip::Intercept::StopInterception(const char *str)
{
    if (interceptActive_) {
        debugs(89, DBG_IMPORTANT, "Stopping IP interception: " << str);
        interceptActive_ = 0;
    }
}

bool
Ip::Intercept::NetfilterInterception(const Comm::ConnectionPointer &newConn, int silent)
{
#if LINUX_NETFILTER
    struct sockaddr_in lookup;
    socklen_t len = sizeof(struct sockaddr_in);
    newConn->local.GetSockAddr(lookup);

    /** \par
     * Try NAT lookup for REDIRECT or DNAT targets. */
    if ( getsockopt(newConn->fd, IPPROTO_IP, SO_ORIGINAL_DST, &lookup, &len) != 0) {
        if (!silent) {
            debugs(89, DBG_IMPORTANT, HERE << " NF getsockopt(SO_ORIGINAL_DST) failed on " << newConn << ": " << xstrerror());
            lastReported_ = squid_curtime;
        }
        debugs(89, 9, HERE << "address: " << newConn);
        return false;
    } else {
        newConn->local = lookup;
        debugs(89, 5, HERE << "address NAT: " << newConn);
        return true;
    }
#endif
    return false;
}

bool
Ip::Intercept::NetfilterTransparent(const Comm::ConnectionPointer &newConn, int silent)
{
#if LINUX_NETFILTER
    /* Trust the user configured properly. If not no harm done.
     * We will simply attempt a bind outgoing on our own IP.
     */
    newConn->remote.SetPort(0); // allow random outgoing port to prevent address clashes
    debugs(89, 5, HERE << "address TPROXY: " << newConn);
    return true;
#else
    return false;
#endif
}

bool
Ip::Intercept::IpfwInterception(const Comm::ConnectionPointer &newConn, int silent)
{
#if IPFW_TRANSPARENT
    struct sockaddr_storage lookup;
    socklen_t len = sizeof(struct sockaddr_storage);
    newConn->local.GetSockAddr(lookup, AF_INET);

    /** \par
     * Try lookup for IPFW interception. */
    if ( getsockname(newConn->fd, (struct sockaddr*)&lookup, &len) != 0 ) {
        if ( !silent ) {
            debugs(89, DBG_IMPORTANT, HERE << " IPFW getsockname(...) failed: " << xstrerror());
            lastReported_ = squid_curtime;
        }
        debugs(89, 9, HERE << "address: " << newConn);
        return false;
    } else {
        newConn->local = lookup;
        debugs(89, 5, HERE << "address NAT: " << newConn);
        return true;
    }
#endif
    return false;
}

bool
Ip::Intercept::IpfInterception(const Comm::ConnectionPointer &newConn, int silent)
{
#if IPF_TRANSPARENT  /* --enable-ipf-transparent */

    struct natlookup natLookup;
    static int natfd = -1;
    int x;

    // all fields must be set to 0
    memset(&natLookup, 0, sizeof(natLookup));
    // for NAT lookup set local and remote IP:port's
    natLookup.nl_inport = htons(newConn->local.GetPort());
    newConn->local.GetInAddr(natLookup.nl_inip);
    natLookup.nl_outport = htons(newConn->remote.GetPort());
    newConn->remote.GetInAddr(natLookup.nl_outip);
    // ... and the TCP flag
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
            debugs(89, DBG_IMPORTANT, "IPF (IPFilter) NAT open failed: " << xstrerror());
            lastReported_ = squid_curtime;
            return false;
        }
    }

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
    struct ipfobj obj;
    memset(&obj, 0, sizeof(obj));
    obj.ipfo_rev = IPFILTER_VERSION;
    obj.ipfo_size = sizeof(natLookup);
    obj.ipfo_ptr = &natLookup;
    obj.ipfo_type = IPFOBJ_NATLOOKUP;

    x = ioctl(natfd, SIOCGNATL, &obj);
#else
    /*
    * IP-Filter changed the type for SIOCGNATL between
    * 3.3 and 3.4.  It also changed the cmd value for
    * SIOCGNATL, so at least we can detect it.  We could
    * put something in configure and use ifdefs here, but
    * this seems simpler.
    */
    static int siocgnatl_cmd = SIOCGNATL & 0xff;
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
                debugs(89, DBG_IMPORTANT, "IPF (IPFilter) NAT lookup failed: ioctl(SIOCGNATL) (v=" << IPFILTER_VERSION << "): " << xstrerror());
                lastReported_ = squid_curtime;
            }

            close(natfd);
            natfd = -1;
        }

        debugs(89, 9, HERE << "address: " << newConn);
        return false;
    } else {
        newConn->local = natLookup.nl_realip;
        newConn->local.SetPort(ntohs(natLookup.nl_realport));
        debugs(89, 5, HERE << "address NAT: " << newConn);
        return true;
    }

#endif /* --enable-ipf-transparent */
    return false;
}

bool
Ip::Intercept::PfInterception(const Comm::ConnectionPointer &newConn, int silent)
{
#if PF_TRANSPARENT  /* --enable-pf-transparent */

    struct pfioc_natlook nl;
    static int pffd = -1;

    if (pffd < 0)
        pffd = open("/dev/pf", O_RDONLY);

    if (pffd < 0) {
        if (!silent) {
            debugs(89, DBG_IMPORTANT, HERE << "PF open failed: " << xstrerror());
            lastReported_ = squid_curtime;
        }
        return false;
    }

    memset(&nl, 0, sizeof(struct pfioc_natlook));
    newConn->remote.GetInAddr(nl.saddr.v4);
    nl.sport = htons(newConn->remote.GetPort());

    newConn->local.GetInAddr(nl.daddr.v4);
    nl.dport = htons(newConn->local.GetPort());

    nl.af = AF_INET;
    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;

    if (ioctl(pffd, DIOCNATLOOK, &nl)) {
        if (errno != ENOENT) {
            if (!silent) {
                debugs(89, DBG_IMPORTANT, HERE << "PF lookup failed: ioctl(DIOCNATLOOK)");
                lastReported_ = squid_curtime;
            }
            close(pffd);
            pffd = -1;
        }
        debugs(89, 9, HERE << "address: " << newConn);
        return false;
    } else {
        newConn->local = nl.rdaddr.v4;
        newConn->local.SetPort(ntohs(nl.rdport));
        debugs(89, 5, HERE << "address NAT: " << newConn);
        return true;
    }

#endif /* --enable-pf-transparent */
    return false;
}

bool
Ip::Intercept::Lookup(const Comm::ConnectionPointer &newConn, const Comm::ConnectionPointer &listenConn)
{
    /* --enable-linux-netfilter    */
    /* --enable-ipfw-transparent   */
    /* --enable-ipf-transparent    */
    /* --enable-pf-transparent     */
#if IPF_TRANSPARENT || LINUX_NETFILTER || IPFW_TRANSPARENT || PF_TRANSPARENT

#if 0
    // Crop interception errors down to one per minute.
    int silent = (squid_curtime - lastReported_ > 60 ? 0 : 1);
#else
    // Show all interception errors.
    int silent = 0;
#endif

    debugs(89, 5, HERE << "address BEGIN: me/client= " << newConn->local << ", destination/me= " << newConn->remote);

    newConn->flags |= (listenConn->flags & (COMM_TRANSPARENT|COMM_INTERCEPTION));

    /* NP: try TPROXY first, its much quieter than NAT when non-matching */
    if (transparentActive_ && listenConn->flags&COMM_TRANSPARENT) {
        if (NetfilterTransparent(newConn, silent)) return true;
    }

    /* NAT is only available in IPv4 */
    if ( !newConn->local.IsIPv4()  ) return false;
    if ( !newConn->remote.IsIPv4() ) return false;

    if (interceptActive_ && listenConn->flags&COMM_INTERCEPTION) {
        /* NAT methods that use sock-opts to return client address */
        if (NetfilterInterception(newConn, silent)) return true;
        if (IpfwInterception(newConn, silent)) return true;

        /* NAT methods that use ioctl to return client address AND destination address */
        if (PfInterception(newConn, silent)) return true;
        if (IpfInterception(newConn, silent)) return true;
    }

#else /* none of the transparent options configured */
    debugs(89, DBG_IMPORTANT, "WARNING: transparent proxying not supported");
#endif

    return false;
}

bool
Ip::Intercept::ProbeForTproxy(Ip::Address &test)
{
    debugs(3, 3, "Detect TPROXY support on port " << test);

#if defined(IP_TRANSPARENT)

    int tos = 1;
    int tmp_sock = -1;

    /* Probe to see if the Kernel TPROXY support is IPv6-enabled */
    if (test.IsIPv6()) {
        debugs(3, 3, "...Probing for IPv6 TPROXY support.");

        struct sockaddr_in6 tmp_ip6;
        Ip::Address tmp = "::2";
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
        Ip::Address tmp = "127.0.0.2";
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
    return false;
}
