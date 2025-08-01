/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 89    NAT / IP Interception */

// Enable hack to workaround Solaris 10 IPFilter breakage
#define BUILDING_SQUID_IP_INTERCEPT_CC 1

#include "squid.h"
#include "comm/Connection.h"
#include "compat/socket.h"
#include "compat/unistd.h"
#include "fde.h"
#include "ip/Intercept.h"
#include "ip/tools.h"
#include "src/tools.h"

#include <cerrno>

#if IPF_TRANSPARENT

#if !defined(IPFILTER_VERSION)
#define IPFILTER_VERSION        5000004
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
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
#if USE_SOLARIS_IPFILTER_MINOR_T_HACK
#undef minor_t
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
/* <climits> must be before including netfilter_ipv4.h */
#include <climits>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#if HAVE_LINUX_NETFILTER_IPV6_IP6_TABLES_H
/* 2013-07-01: Pablo the Netfilter maintainer is rejecting patches
 * which will enable C++ compilers to build the Netfilter public headers.
 * We can auto-detect its presence and attempt to use in case he ever
 * changes his mind or things get cleaned up some other way.
 * But until then are usually forced to hard-code the getsockopt() code
 * for IPv6 NAT lookups.
 */
#include <linux/netfilter_ipv6/ip6_tables.h>
#endif
#if !defined(IP6T_SO_ORIGINAL_DST)
#define IP6T_SO_ORIGINAL_DST    80  // stolen with prejudice from the above file.
#endif
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

bool
Ip::Intercept::NetfilterInterception(const Comm::ConnectionPointer &newConn)
{
#if LINUX_NETFILTER
    struct sockaddr_storage lookup;
    socklen_t len = newConn->local.isIPv6() ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    newConn->local.getSockAddr(lookup, AF_UNSPEC);

    /** \par
     * Try NAT lookup for REDIRECT or DNAT targets. */
    if ( xgetsockopt(newConn->fd,
                     newConn->local.isIPv6() ? IPPROTO_IPV6 : IPPROTO_IP,
                     newConn->local.isIPv6() ? IP6T_SO_ORIGINAL_DST : SO_ORIGINAL_DST,
                     &lookup,
                     &len) != 0) {
        const auto xerrno = errno;
        debugs(89, DBG_IMPORTANT, "ERROR: NF getsockopt(ORIGINAL_DST) failed on " << newConn << ": " << xstrerr(xerrno));
        return false;
    } else {
        newConn->local = lookup;
        debugs(89, 5, "address NAT: " << newConn);
        return true;
    }
#else
    (void)newConn;
#endif
    return false;
}

void
Ip::Intercept::StartTransparency()
{
    // --enable-linux-netfilter
    // --enable-pf-transparent
    // --enable-ipfw-transparent
#if (LINUX_NETFILTER && defined(IP_TRANSPARENT)) || \
    (PF_TRANSPARENT && defined(SO_BINDANY)) || \
    (IPFW_TRANSPARENT && defined(IP_BINDANY))
    transparentActive_ = 1;
#else
    throw TextException("requires TPROXY feature to be enabled by ./configure", Here());
#endif
}

void
Ip::Intercept::StartInterception()
{
    // --enable-linux-netfilter
    // --enable-ipfw-transparent
    // --enable-ipf-transparent
    // --enable-pf-transparent
#if IPF_TRANSPARENT || LINUX_NETFILTER || IPFW_TRANSPARENT || PF_TRANSPARENT
    interceptActive_ = 1;
#else
    throw TextException("requires NAT Interception feature to be enabled by ./configure", Here());
#endif
}

bool
Ip::Intercept::IpfwInterception(const Comm::ConnectionPointer &newConn)
{
#if IPFW_TRANSPARENT
    return UseInterceptionAddressesLookedUpEarlier(__FUNCTION__, newConn);
#else
    (void)newConn;
    return false;
#endif
}

/// Assume that getsockname() has been called already and provided the necessary
/// TCP packet details. There is no way to identify whether they came from NAT.
/// Trust the user configured properly.
bool
Ip::Intercept::UseInterceptionAddressesLookedUpEarlier(const char * const caller, const Comm::ConnectionPointer &newConn)
{
    // paranoid: ./configure should prohibit these combinations
#if LINUX_NETFILTER && PF_TRANSPARENT && !USE_NAT_DEVPF
    static_assert(!"--enable-linux-netfilter is incompatible with --enable-pf-transparent --without-nat-devpf");
#endif
#if LINUX_NETFILTER && IPFW_TRANSPARENT
    static_assert(!"--enable-linux-netfilter is incompatible with --enable-ipfw-transparent");
#endif
    // --enable-linux-netfilter is compatible with --enable-ipf-transparent

    debugs(89, 5, caller << " uses " << newConn);
    return true;
}

bool
Ip::Intercept::IpfInterception(const Comm::ConnectionPointer &newConn)
{
#if IPF_TRANSPARENT  /* --enable-ipf-transparent */

    struct natlookup natLookup;
    static int natfd = -1;
    int x;

    // all fields must be set to 0
    memset(&natLookup, 0, sizeof(natLookup));
    // for NAT lookup set local and remote IP:port's
    if (newConn->remote.isIPv6()) {
#if HAVE_STRUCT_NATLOOKUP_NL_INIPADDR_IN6
        natLookup.nl_v = 6;
        newConn->local.getInAddr(natLookup.nl_inipaddr.in6);
        newConn->remote.getInAddr(natLookup.nl_outipaddr.in6);
    }
    else {
        natLookup.nl_v = 4;
        newConn->local.getInAddr(natLookup.nl_inipaddr.in4);
        newConn->remote.getInAddr(natLookup.nl_outipaddr.in4);
    }
#else /* HAVE_STRUCT_NATLOOKUP_NL_INIPADDR_IN6 */
        // warn once every 10 at critical level, then push down a level each repeated event
        static int warningLevel = DBG_CRITICAL;
        debugs(89, warningLevel, "Your IPF (IPFilter) NAT does not support IPv6. Please upgrade it.");
        warningLevel = (warningLevel + 1) % 10;
        return false;
    }
    newConn->local.getInAddr(natLookup.nl_inip);
    newConn->remote.getInAddr(natLookup.nl_outip);
#endif /* HAVE_STRUCT_NATLOOKUP_NL_INIPADDR_IN6 */
    natLookup.nl_inport = htons(newConn->local.port());
    natLookup.nl_outport = htons(newConn->remote.port());
    // ... and the TCP flag
    natLookup.nl_flags = IPN_TCP;

    if (natfd < 0) {
        int save_errno;
        enter_suid();
#ifdef IPNAT_NAME
        natfd = xopen(IPNAT_NAME, O_RDONLY, 0);
#else
        natfd = xopen(IPL_NAT, O_RDONLY, 0);
#endif
        save_errno = errno;
        leave_suid();
        errno = save_errno;
    }

    if (natfd < 0) {
        const auto xerrno = errno;
        debugs(89, DBG_IMPORTANT, "ERROR: IPF (IPFilter) NAT open failed: " << xstrerr(xerrno));
        return false;
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

#endif /* defined(IPFILTER_VERSION) ... */
    if (x < 0) {
        const auto xerrno = errno;
        if (xerrno != ESRCH) {
            debugs(89, DBG_IMPORTANT, "ERROR: IPF (IPFilter) NAT lookup failed: ioctl(SIOCGNATL) (v=" << IPFILTER_VERSION << "): " << xstrerr(xerrno));
            xclose(natfd);
            natfd = -1;
        }

        debugs(89, 9, "address: " << newConn);
        return false;
    } else {
#if HAVE_STRUCT_NATLOOKUP_NL_REALIPADDR_IN6
        if (newConn->remote.isIPv6())
            newConn->local = natLookup.nl_realipaddr.in6;
        else
            newConn->local = natLookup.nl_realipaddr.in4;
#else
        newConn->local = natLookup.nl_realip;
#endif
        newConn->local.port(ntohs(natLookup.nl_realport));
        debugs(89, 5, "address NAT: " << newConn);
        return true;
    }

#else
    (void)newConn;
#endif /* --enable-ipf-transparent */
    return false;
}

bool
Ip::Intercept::PfInterception(const Comm::ConnectionPointer &newConn)
{
#if PF_TRANSPARENT  /* --enable-pf-transparent */

#if !USE_NAT_DEVPF
    return UseInterceptionAddressesLookedUpEarlier("recent PF version", newConn);

#else /* USE_NAT_DEVPF / --with-nat-devpf */

    struct pfioc_natlook nl;
    static int pffd = -1;

    if (pffd < 0)
        pffd = xopen("/dev/pf", O_RDONLY);

    if (pffd < 0) {
        const auto xerrno = errno;
        debugs(89, DBG_IMPORTANT, "ERROR: PF open failed: " << xstrerr(xerrno));
        return false;
    }

    memset(&nl, 0, sizeof(struct pfioc_natlook));

    if (newConn->remote.isIPv6()) {
        newConn->remote.getInAddr(nl.saddr.v6);
        newConn->local.getInAddr(nl.daddr.v6);
        nl.af = AF_INET6;
    } else {
        newConn->remote.getInAddr(nl.saddr.v4);
        newConn->local.getInAddr(nl.daddr.v4);
        nl.af = AF_INET;
    }

    nl.sport = htons(newConn->remote.port());
    nl.dport = htons(newConn->local.port());

    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;

    if (ioctl(pffd, DIOCNATLOOK, &nl)) {
        const auto xerrno = errno;
        if (xerrno != ENOENT) {
            debugs(89, DBG_IMPORTANT, "ERROR: PF lookup failed: ioctl(DIOCNATLOOK): " << xstrerr(xerrno));
            xclose(pffd);
            pffd = -1;
        }
        debugs(89, 9, "address: " << newConn);
        return false;
    } else {
        if (newConn->remote.isIPv6())
            newConn->local = nl.rdaddr.v6;
        else
            newConn->local = nl.rdaddr.v4;
        newConn->local.port(ntohs(nl.rdport));
        debugs(89, 5, "address NAT: " << newConn);
        return true;
    }
#endif /* --with-nat-devpf */
#else
    (void)newConn;
#endif /* --enable-pf-transparent */
    return false;
}

bool
Ip::Intercept::LookupNat(const Comm::Connection &aConn)
{
    debugs(89, 5, "address BEGIN: me/client= " << aConn.local << ", destination/me= " << aConn.remote);
    assert(interceptActive_);

    Comm::ConnectionPointer newConn = &aConn;
    return NetfilterInterception(newConn) || IpfwInterception(newConn) || // use sock-opts to return client address
           PfInterception(newConn) || IpfInterception(newConn); // use ioctl to return client address AND destination address
}

bool
Ip::Intercept::ProbeForTproxy(Ip::Address &test)
{
    bool doneSuid = false;

#if _SQUID_LINUX_ && defined(IP_TRANSPARENT) // Linux
# define soLevel SOL_IP
# define soFlag  IP_TRANSPARENT

#elif defined(SO_BINDANY) // OpenBSD 4.7+ and NetBSD with PF
# define soLevel SOL_SOCKET
# define soFlag  SO_BINDANY
    enter_suid();
    doneSuid = true;

#elif defined(IP_BINDANY) // FreeBSD with IPFW
# define soLevel IPPROTO_IP
# define soFlag  IP_BINDANY
    enter_suid();
    doneSuid = true;

#endif

#if defined(soLevel) && defined(soFlag)

    debugs(3, 3, "Detect TPROXY support on port " << test);

    if (!Ip::EnableIpv6 && test.isIPv6() && !test.setIPv4()) {
        debugs(3, DBG_CRITICAL, "Cannot use TPROXY for " << test << " because IPv6 support is disabled");
        if (doneSuid)
            leave_suid();
        return false;
    }

    int tos = 1;
    int tmp_sock = -1;

    /* Probe to see if the Kernel TPROXY support is IPv6-enabled */
    if (test.isIPv6()) {
        debugs(3, 3, "...Probing for IPv6 TPROXY support.");

        struct sockaddr_in6 tmp_ip6;
        Ip::Address tmp = "::2";
        tmp.port(0);
        tmp.getSockAddr(tmp_ip6);

        if ( (tmp_sock = xsocket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)) >= 0 &&
                xsetsockopt(tmp_sock, soLevel, soFlag, &tos, sizeof(int)) == 0 &&
                xbind(tmp_sock, (struct sockaddr*)&tmp_ip6, sizeof(struct sockaddr_in6)) == 0 ) {

            debugs(3, 3, "IPv6 TPROXY support detected. Using.");
            xclose(tmp_sock);
            if (doneSuid)
                leave_suid();
            return true;
        }
        if (tmp_sock >= 0) {
            xclose(tmp_sock);
            tmp_sock = -1;
        }
    }

    if ( test.isIPv6() && !test.setIPv4() ) {
        debugs(3, DBG_CRITICAL, "TPROXY lacks IPv6 support for " << test );
        if (doneSuid)
            leave_suid();
        return false;
    }

    /* Probe to see if the Kernel TPROXY support is IPv4-enabled (aka present) */
    if (test.isIPv4()) {
        debugs(3, 3, "...Probing for IPv4 TPROXY support.");

        struct sockaddr_in tmp_ip4;
        Ip::Address tmp = "127.0.0.2";
        tmp.port(0);
        tmp.getSockAddr(tmp_ip4);

        if ( (tmp_sock = xsocket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) >= 0 &&
                xsetsockopt(tmp_sock, soLevel, soFlag, &tos, sizeof(int)) == 0 &&
                xbind(tmp_sock, (struct sockaddr*)&tmp_ip4, sizeof(struct sockaddr_in)) == 0 ) {

            debugs(3, 3, "IPv4 TPROXY support detected. Using.");
            xclose(tmp_sock);
            if (doneSuid)
                leave_suid();
            return true;
        }
        if (tmp_sock >= 0) {
            xclose(tmp_sock);
        }
    }

#else
    debugs(3, 3, "TPROXY setsockopt() not supported on this platform. Disabling TPROXY on port " << test);

#endif
    if (doneSuid)
        leave_suid();
    return false;
}

