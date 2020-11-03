/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 89    EUI-48 Lookup */

#include "squid.h"

#if USE_SQUID_EUI

#include "Debug.h"
#include "eui/Eui48.h"
#include "globals.h"
#include "ip/Address.h"

#include <cerrno>

/* START Legacy includes pattern */
/* TODO: clean this up so we do not have per-OS requirements.
         The files are checked for existence individually
         and can be wrapped
 */

#if _SQUID_WINDOWS_
struct arpreq {

    Ip::Address arp_pa;   /* protocol address */

    struct sockaddr arp_ha;   /* hardware address */
    int arp_flags;            /* flags */
};
#if HAVE_IPHLPAPI_H
#include <iphlpapi.h>
#endif
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_SOCKIO_H
/* required by Solaris */
#include <sys/sockio.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#if HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

/* ==== BEGIN EUI LOOKUP SUPPORT ============================================= */

/*
 * From:    dale@server.ctam.bitmcnit.bryansk.su (Dale)
 * To:      wessels@nlanr.net
 * Subject: Another Squid patch... :)
 * Date:    Thu, 04 Dec 1997 19:55:01 +0300
 * ============================================================================
 *
 * Working on setting up a proper firewall for a network containing some
 * Win'95 computers at our Univ, I've discovered that some smart students
 * avoid the restrictions easily just changing their IP addresses in Win'95
 * Control Panel... It has been getting boring, so I took Squid-1.1.18
 * sources and added a new acl type for hard-wired access control:
 *
 * acl <name> arp <Ethernet address> ...
 *
 * For example,
 *
 * acl students arp 00:00:21:55:ed:22 00:00:21:ff:55:38
 *
 * NOTE: Linux code by David Luyer <luyer@ucs.uwa.edu.au>.
 *       Original (BSD-specific) code no longer works.
 *       Solaris code by R. Gancarz <radekg@solaris.elektrownia-lagisza.com.pl>
 */

bool
Eui::Eui48::decode(const char *asc)
{
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;

    if (sscanf(asc, "%x:%x:%x:%x:%x:%x", &a1, &a2, &a3, &a4, &a5, &a6) != 6) {
        debugs(28, DBG_CRITICAL, "Decode EUI-48: Invalid ethernet address '" << asc << "'");
        clear();
        return false;       /* This is not valid address */
    }

    eui[0] = (u_char) a1;
    eui[1] = (u_char) a2;
    eui[2] = (u_char) a3;
    eui[3] = (u_char) a4;
    eui[4] = (u_char) a5;
    eui[5] = (u_char) a6;

    debugs(28, 4, "id=" << (void*)this << " decoded " << asc);
    return true;
}

bool
Eui::Eui48::encode(char *buf, const int len) const
{
    if (len < SZ_EUI48_BUF)
        return false;

    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             eui[0] & 0xff, eui[1] & 0xff,
             eui[2] & 0xff, eui[3] & 0xff,
             eui[4] & 0xff, eui[5] & 0xff);

    debugs(28, 4, "id=" << (void*)this << " encoded " << buf);
    return true;
}

// return binary representation of the EUI
bool
Eui::Eui48::lookup(const Ip::Address &c)
{
    Ip::Address ipAddr = c;
    ipAddr.port(0);

#if _SQUID_LINUX_

    unsigned char ifbuffer[sizeof(struct ifreq) * 64];
    struct ifconf ifc;

    struct ifreq *ifr;
    int offset;

    /* IPv6 builds do not provide the first http_port as an IPv4 socket for ARP */
    int tmpSocket = socket(AF_INET,SOCK_STREAM,0);
    if (tmpSocket < 0) {
        int xerrno = errno;
        debugs(28, DBG_IMPORTANT, "Attempt to open socket for EUI retrieval failed: " << xstrerr(xerrno));
        clear();
        return false;
    }

    /*
     * The linux kernel 2.2 maintains per interface ARP caches and
     * thus requires an interface name when doing ARP queries.
     *
     * The older 2.0 kernels appear to use a unified ARP cache,
     * and require an empty interface name
     *
     * To support both, we attempt the lookup with a blank interface
     * name first. If that does not succeed, the try each interface
     * in turn
     */

    /*
     * Set up structures for ARP lookup with blank interface name
     */
    struct arpreq arpReq;
    memset(&arpReq, '\0', sizeof(arpReq));

    struct sockaddr_in *sa = (struct sockaddr_in*)&arpReq.arp_pa;
    ipAddr.getSockAddr(*sa);

    /* Query ARP table */
    debugs(28, 4, "id=" << (void*)this << " query ARP table");
    if (ioctl(tmpSocket, SIOCGARP, &arpReq) != -1) {
        /* Skip non-ethernet interfaces */
        close(tmpSocket);

        if (arpReq.arp_ha.sa_family != ARPHRD_ETHER) {
            debugs(28, 4, "id=" << (void*)this << " ... not an Ethernet interface: " << arpReq.arp_ha.sa_data);
            clear();
            return false;
        }

        debugs(28, 4, "id=" << (void*)this << " got address "<< std::setfill('0') << std::hex <<
               std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

        set(arpReq.arp_ha.sa_data, 6);
        return true;
    }

    /* lookup list of interface names */
    ifc.ifc_len = sizeof(ifbuffer);

    ifc.ifc_buf = (char *)ifbuffer;

    if (ioctl(tmpSocket, SIOCGIFCONF, &ifc) < 0) {
        int xerrno = errno;
        debugs(28, DBG_IMPORTANT, "Attempt to retrieve interface list failed: " << xstrerr(xerrno));
        clear();
        close(tmpSocket);
        return false;
    }

    if (ifc.ifc_len > (int)sizeof(ifbuffer)) {
        debugs(28, DBG_IMPORTANT, "Interface list too long - " << ifc.ifc_len);
        clear();
        close(tmpSocket);
        return false;
    }

    /* Attempt ARP lookup on each interface */
    offset = 0;
    debugs(28, 4, "id=" << (void*)this << " query ARP on each interface (" << ifc.ifc_len << " found)");
    while (offset < ifc.ifc_len) {

        ifr = (struct ifreq *) (ifbuffer + offset);
        offset += sizeof(*ifr);

        debugs(28, 4, "id=" << (void*)this << " found interface " << ifr->ifr_name);

        /* Skip loopback and aliased interfaces */
        if (!strncmp(ifr->ifr_name, "lo", 2))
            continue;

        if (strchr(ifr->ifr_name, ':'))
            continue;

        debugs(28, 4, "id=" << (void*)this << " looking up ARP address for " << ipAddr << " on " << ifr->ifr_name);

        /* Set up structures for ARP lookup */

        memset(&arpReq, '\0', sizeof(arpReq));

        sa = (sockaddr_in*)&arpReq.arp_pa;
        ipAddr.getSockAddr(*sa);

        strncpy(arpReq.arp_dev, ifr->ifr_name, sizeof(arpReq.arp_dev) - 1);

        arpReq.arp_dev[sizeof(arpReq.arp_dev) - 1] = '\0';

        /* Query ARP table */
        if (-1 == ioctl(tmpSocket, SIOCGARP, &arpReq)) {
            int xerrno = errno;
            //  Query failed.  Do not log failed lookups or "device not supported"
            if (ENXIO != xerrno && ENODEV != xerrno)
                debugs(28, DBG_IMPORTANT, "ARP query " << ipAddr << " failed: " << ifr->ifr_name << ": " << xstrerr(xerrno));

            continue;
        }

        /* Skip non-ethernet interfaces */
        if (arpReq.arp_ha.sa_family != ARPHRD_ETHER) {
            debugs(28, 4, "id=" << (void*)this << "... not an Ethernet interface");
            continue;
        }

        debugs(28, 4, "id=" << (void*)this << " got address "<< std::setfill('0') << std::hex <<
               std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff)  << " on "<<
               std::setfill(' ') << ifr->ifr_name);

        set(arpReq.arp_ha.sa_data, 6);

        /*
         * Should we stop looking here? Can the same IP address
         * exist on multiple interfaces?
         */

        /* AYJ: 2009-10-06: for now we have to. We can only store one EUI at a time. */
        close(tmpSocket);
        return true;
    }

    close(tmpSocket);

#elif _SQUID_SOLARIS_

    /* IPv6 builds do not provide the first http_port as an IPv4 socket for ARP */
    int tmpSocket = socket(AF_INET,SOCK_STREAM,0);
    if (tmpSocket < 0) {
        int xerrno = errno;
        debugs(28, DBG_IMPORTANT, "Attempt to open socket for EUI retrieval failed: " << xstrerr(xerrno));
        clear();
        return false;
    }

    /* Set up structures for ARP lookup with blank interface name */
    struct arpreq arpReq;
    memset(&arpReq, '\0', sizeof(arpReq));

    struct sockaddr_in *sa = (struct sockaddr_in*)&arpReq.arp_pa;
    ipAddr.getSockAddr(*sa);

    /* Query ARP table */
    if (ioctl(tmpSocket, SIOCGARP, &arpReq) != -1) {
        /*
        *  Solaris (at least 2.6/x86) does not use arp_ha.sa_family -
        * it returns 00:00:00:00:00:00 for non-ethernet media
        */
        close(tmpSocket);

        if (arpReq.arp_ha.sa_data[0] == 0 &&
                arpReq.arp_ha.sa_data[1] == 0 &&
                arpReq.arp_ha.sa_data[2] == 0 &&
                arpReq.arp_ha.sa_data[3] == 0 &&
                arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0) {
            clear();
            return false;
        }

        debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
               std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

        set(arpReq.arp_ha.sa_data, 6);
        return true;
    } else {
        close(tmpSocket);
    }

#elif _SQUID_FREEBSD_ || _SQUID_NETBSD_ || _SQUID_OPENBSD_ || _SQUID_DRAGONFLY_ || _SQUID_KFREEBSD_

    int mib[6];

    size_t needed;

    char *lim, *buf, *next;

    struct rt_msghdr *rtm;

    struct sockaddr_inarp *sin;

    struct sockaddr_dl *sdl;

    /*
    * Set up structures for ARP lookup with blank interface name
    */
    struct arpreq arpReq;
    memset(&arpReq, '\0', sizeof(arpReq));

    struct sockaddr_in *sa = (struct sockaddr_in*)&arpReq.arp_pa;
    ipAddr.getSockAddr(*sa);

    /* Query ARP table */
    mib[0] = CTL_NET;

    mib[1] = PF_ROUTE;

    mib[2] = 0;

    mib[3] = AF_INET;

    mib[4] = NET_RT_FLAGS;

#if defined(RTF_LLDATA)
    mib[5] = RTF_LLDATA;
#else
    mib[5] = RTF_LLINFO;
#endif

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
        debugs(28, DBG_CRITICAL, "Can't estimate ARP table size!");
        clear();
        return false;
    }

    if ((buf = (char *)xmalloc(needed)) == NULL) {
        debugs(28, DBG_CRITICAL, "Can't allocate temporary ARP table!");
        clear();
        return false;
    }

    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        debugs(28, DBG_CRITICAL, "Can't retrieve ARP table!");
        xfree(buf);
        clear();
        return false;
    }

    lim = buf + needed;

    for (next = buf; next < lim; next += rtm->rtm_msglen) {

        rtm = (struct rt_msghdr *) next;

        sin = (struct sockaddr_inarp *) (rtm + 1);
        /*sdl = (struct sockaddr_dl *) (sin + 1); */

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

        sdl = (struct sockaddr_dl *)((char *) sin + ROUNDUP(sin->sin_len));

        if (ipAddr == sin->sin_addr) {
            if (sdl->sdl_alen) {

                arpReq.arp_ha.sa_len = sizeof(struct sockaddr);
                arpReq.arp_ha.sa_family = AF_UNSPEC;
                memcpy(arpReq.arp_ha.sa_data, LLADDR(sdl), sdl->sdl_alen);
            }
        }
    }

    xfree(buf);

    if (arpReq.arp_ha.sa_data[0] == 0 && arpReq.arp_ha.sa_data[1] == 0 &&
            arpReq.arp_ha.sa_data[2] == 0 && arpReq.arp_ha.sa_data[3] == 0 &&
            arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0) {
        clear();
        return false;
    }

    debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
           std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

    set(arpReq.arp_ha.sa_data, 6);
    return true;

#elif _SQUID_WINDOWS_

    DWORD           dwNetTable = 0;

    DWORD           ipNetTableLen = 0;

    PMIB_IPNETTABLE NetTable = NULL;

    DWORD            i;

    struct arpreq arpReq;
    memset(&arpReq, '\0', sizeof(arpReq));

    /* Get size of Windows ARP table */
    if (GetIpNetTable(NetTable, &ipNetTableLen, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        debugs(28, DBG_CRITICAL, "Can't estimate ARP table size!");
        clear();
        return false;
    }

    /* Allocate space for ARP table and assign pointers */
    if ((NetTable = (PMIB_IPNETTABLE)xmalloc(ipNetTableLen)) == NULL) {
        debugs(28, DBG_CRITICAL, "Can't allocate temporary ARP table!");
        clear();
        return false;
    }

    /* Get actual ARP table */
    if ((dwNetTable = GetIpNetTable(NetTable, &ipNetTableLen, FALSE)) != NO_ERROR) {
        debugs(28, DBG_CRITICAL, "Can't retrieve ARP table!");
        xfree(NetTable);
        clear();
        return false;
    }

    /* Find MAC address from net table */
    for (i = 0 ; i < NetTable->dwNumEntries ; ++i) {
        in_addr a;
        a.s_addr = NetTable->table[i].dwAddr;
        if (c == a && (NetTable->table[i].dwType > 2)) {
            arpReq.arp_ha.sa_family = AF_UNSPEC;
            memcpy(arpReq.arp_ha.sa_data, NetTable->table[i].bPhysAddr, NetTable->table[i].dwPhysAddrLen);
        }
    }

    xfree(NetTable);

    if (arpReq.arp_ha.sa_data[0] == 0 && arpReq.arp_ha.sa_data[1] == 0 &&
            arpReq.arp_ha.sa_data[2] == 0 && arpReq.arp_ha.sa_data[3] == 0 &&
            arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0) {
        clear();
        return false;
    }

    debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
           std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

    set(arpReq.arp_ha.sa_data, 6);
    return true;

#else

    debugs(28, DBG_CRITICAL, "ERROR: ARP / MAC / EUI-* operations not supported on this operating system.");

#endif
    /*
     * Address was not found on any interface
     */
    debugs(28, 3, "id=" << (void*)this << ' ' << ipAddr << " NOT found");

    clear();
    return false;
}

/* ==== END EUI LOOKUP SUPPORT =============================================== */

#endif /* USE_SQUID_EUI */

