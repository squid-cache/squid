/*
 * $Id: ACLARP.cc,v 1.24 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "config.h"
#ifdef _SQUID_CYGWIN_
#include <squid_windows.h>
#endif
#include "squid.h"

#ifdef _SQUID_WIN32_

struct arpreq
{

    struct sockaddr arp_pa;   /* protocol address */

    struct sockaddr arp_ha;   /* hardware address */
    int arp_flags;            /* flags */
};

#include <Iphlpapi.h>
#else

#ifdef _SQUID_SOLARIS_
#include <sys/sockio.h>
#else
#include <sys/sysctl.h>
#endif
#ifdef _SQUID_LINUX_
#include <net/if_arp.h>
#include <sys/ioctl.h>
#else
#include <net/if_dl.h>
#endif
#include <net/route.h>
#include <net/if.h>
#if defined(_SQUID_FREEBSD_) || defined(_SQUID_NETBSD_) || defined(_SQUID_OPENBSD_)
#include <net/if_arp.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#endif

#include "ACLARP.h"
#include "wordlist.h"

#if !USE_ARP_ACL
#error USE_ARP_ACL Not defined
#endif
static void aclParseArpList(SplayNode<acl_arp_data *> **curlist);
static int decode_eth(const char *asc, char *eth);
static int aclMatchArp(SplayNode<acl_arp_data *> **dataptr, struct IN_ADDR c);
static SplayNode<acl_arp_data *>::SPLAYCMP aclArpCompare;
static SplayNode<acl_arp_data *>::SPLAYWALKEE aclDumpArpListWalkee;

ACL::Prototype ACLARP::RegistryProtoype(&ACLARP::RegistryEntry_, "arp");

ACLARP ACLARP::RegistryEntry_("arp");

ACL *
ACLARP::clone() const
{
    return new ACLARP(*this);
}

ACLARP::ACLARP (char const *theClass) : data (NULL), class_ (theClass)
{}

ACLARP::ACLARP (ACLARP const & old) : data (NULL), class_ (old.class_)
{
    /* we don't have copy constructors for the data yet */
    assert (!old.data);
}

ACLARP::~ACLARP()
{
    if (data)
        data->destroy(SplayNode<acl_arp_data*>::DefaultFree);
}

char const *
ACLARP::typeString() const
{
    return class_;
}

bool
ACLARP::empty () const
{
    return data->empty();
}

/* ==== BEGIN ARP ACL SUPPORT ============================================= */

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
 * Contol Panel... It has been getting boring, so I took Squid-1.1.18
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

/*
 * Decode an ascii representation (asc) of an ethernet adress, and place
 * it in eth[6].
 */
static int
decode_eth(const char *asc, char *eth)
{
    int a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;

    if (sscanf(asc, "%x:%x:%x:%x:%x:%x", &a1, &a2, &a3, &a4, &a5, &a6) != 6) {
        debugs(28, 0, "decode_eth: Invalid ethernet address '" << asc << "'");
        return 0;		/* This is not valid address */
    }

    eth[0] = (u_char) a1;
    eth[1] = (u_char) a2;
    eth[2] = (u_char) a3;
    eth[3] = (u_char) a4;
    eth[4] = (u_char) a5;
    eth[5] = (u_char) a6;
    return 1;
}

acl_arp_data *
aclParseArpData(const char *t)
{
    LOCAL_ARRAY(char, eth, 256);
    acl_arp_data *q = new acl_arp_data;
    debugs(28, 5, "aclParseArpData: " << t);

    if (sscanf(t, "%[0-9a-fA-F:]", eth) != 1) {
        debugs(28, 0, "aclParseArpData: Bad ethernet address: '" << t << "'");
        safe_free(q);
        return NULL;
    }

    if (!decode_eth(eth, q->eth)) {
        debugs(28, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, 0, "aclParseArpData: Ignoring invalid ARP acl entry: can't parse '" << eth << "'");
        safe_free(q);
        return NULL;
    }

    return q;
}


/*******************/
/* aclParseArpList */
/*******************/
void
ACLARP::parse()
{
    aclParseArpList (&data);
}

void
aclParseArpList(SplayNode<acl_arp_data *> **curlist)
{
    char *t = NULL;
    SplayNode<acl_arp_data *> **Top = curlist;
    acl_arp_data *q = NULL;

    while ((t = strtokFile())) {
        if ((q = aclParseArpData(t)) == NULL)
            continue;

        *Top = (*Top)->insert(q, aclArpCompare);
    }
}

int
ACLARP::match(ACLChecklist *checklist)
{
    return aclMatchArp(&data, checklist->src_addr);
}

/***************/
/* aclMatchArp */
/***************/
int
aclMatchArp(SplayNode<acl_arp_data *> **dataptr, struct IN_ADDR c)
{
#if defined(_SQUID_LINUX_)

    struct arpreq arpReq;

    struct sockaddr_in ipAddr;

    unsigned char ifbuffer[sizeof(struct ifreq) * 64];

    struct ifconf ifc;

    struct ifreq *ifr;
    int offset;
    SplayNode<acl_arp_data*> **Top = dataptr;
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
    ipAddr.sin_family = AF_INET;
    ipAddr.sin_port = 0;
    ipAddr.sin_addr = c;
    memset(&arpReq, '\0', sizeof(arpReq));

    xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));
    /* Query ARP table */

    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) != -1) {
        /* Skip non-ethernet interfaces */

        if (arpReq.arp_ha.sa_family != ARPHRD_ETHER) {
            return 0;
        }

        debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
               std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

        /* Do lookup */
        acl_arp_data X;
        memcpy (X.eth, arpReq.arp_ha.sa_data, 6);
        *Top = (*Top)->splay(&X, aclArpCompare);
        debugs(28, 3, "aclMatchArp: '" << inet_ntoa(c) << "' " << (splayLastResult ? "NOT found" : "found"));
        return (0 == splayLastResult);
    }

    /* lookup list of interface names */
    ifc.ifc_len = sizeof(ifbuffer);

    ifc.ifc_buf = (char *)ifbuffer;

    if (ioctl(HttpSockets[0], SIOCGIFCONF, &ifc) < 0) {
        debugs(28, 1, "Attempt to retrieve interface list failed: " << xstrerror());
        return 0;
    }

    if (ifc.ifc_len > (int)sizeof(ifbuffer)) {
        debugs(28, 1, "Interface list too long - " << ifc.ifc_len);
        return 0;
    }

    /* Attempt ARP lookup on each interface */
    offset = 0;

    while (offset < ifc.ifc_len) {

        ifr = (struct ifreq *) (ifbuffer + offset);
        offset += sizeof(*ifr);
        /* Skip loopback and aliased interfaces */

        if (0 == strncmp(ifr->ifr_name, "lo", 2))
            continue;

        if (NULL != strchr(ifr->ifr_name, ':'))
            continue;

        debugs(28, 4, "Looking up ARP address for " << inet_ntoa(c) << " on " << ifr->ifr_name);

        /* Set up structures for ARP lookup */
        ipAddr.sin_family = AF_INET;

        ipAddr.sin_port = 0;

        ipAddr.sin_addr = c;

        memset(&arpReq, '\0', sizeof(arpReq));

        xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));

        strncpy(arpReq.arp_dev, ifr->ifr_name, sizeof(arpReq.arp_dev) - 1);

        arpReq.arp_dev[sizeof(arpReq.arp_dev) - 1] = '\0';

        /* Query ARP table */
        if (-1 == ioctl(HttpSockets[0], SIOCGARP, &arpReq)) {
            /*
             * Query failed.  Do not log failed lookups or "device
             * not supported"
             */

            if (ENXIO == errno)
                (void) 0;
            else if (ENODEV == errno)
                (void) 0;
            else
                debugs(28, 1, "ARP query failed: " << ifr->ifr_name << ": " << xstrerror());

            continue;
        }

        /* Skip non-ethernet interfaces */
        if (arpReq.arp_ha.sa_family != ARPHRD_ETHER)
            continue;

        debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
               std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff)  << " on "<<
               std::setfill(' ') << ifr->ifr_name);

        /* Do lookup */
        acl_arp_data X;

        memcpy (X.eth, arpReq.arp_ha.sa_data, 6);

        *Top = (*Top)->splay(&X, aclArpCompare);

        /* Return if match, otherwise continue to other interfaces */
        if (0 == splayLastResult) {
            debugs(28, 3, "aclMatchArp: " << inet_ntoa(c) << " found on " << ifr->ifr_name);
            return 1;
        }

        /*
         * Should we stop looking here? Can the same IP address
         * exist on multiple interfaces?
         */
    }

#elif defined(_SQUID_SOLARIS_)

    struct arpreq arpReq;

    struct sockaddr_in ipAddr;

    SplayNode<acl_arp_data *> **Top = dataptr;

    /*
    * Set up structures for ARP lookup with blank interface name
    */
    ipAddr.sin_family = AF_INET;

    ipAddr.sin_port = 0;

    ipAddr.sin_addr = c;

    memset(&arpReq, '\0', sizeof(arpReq));

    xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));

    /* Query ARP table */
    if (ioctl(HttpSockets[0], SIOCGARP, &arpReq) != -1) {
        /*
        *  Solaris (at least 2.6/x86) does not use arp_ha.sa_family -
        * it returns 00:00:00:00:00:00 for non-ethernet media
        */

        if (arpReq.arp_ha.sa_data[0] == 0 &&
                arpReq.arp_ha.sa_data[1] == 0 &&
                arpReq.arp_ha.sa_data[2] == 0 &&
                arpReq.arp_ha.sa_data[3] == 0 &&
                arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0)
            return 0;

        debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
               std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
               std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

        /* Do lookup */
        *Top = (*Top)->splay((acl_arp_data *)&arpReq.arp_ha.sa_data, aclArpCompare);

        debugs(28, 3, "aclMatchArp: '" << inet_ntoa(c) << "' " << (splayLastResult ? "NOT found" : "found"));

        return (0 == splayLastResult);
    }

#elif defined(_SQUID_FREEBSD_) || defined(_SQUID_NETBSD_) || defined(_SQUID_OPENBSD_)

    struct arpreq arpReq;

    struct sockaddr_in ipAddr;

    SplayNode<acl_arp_data *> **Top = dataptr;

    int mib[6];

    size_t needed;

    char *lim, *buf, *next;

    struct rt_msghdr *rtm;

    struct sockaddr_inarp *sin;

    struct sockaddr_dl *sdl;

    /*
    * Set up structures for ARP lookup with blank interface name
    */
    ipAddr.sin_family = AF_INET;

    ipAddr.sin_port = 0;

    ipAddr.sin_addr = c;

    memset(&arpReq, '\0', sizeof(arpReq));

    xmemcpy(&arpReq.arp_pa, &ipAddr, sizeof(struct sockaddr_in));

    /* Query ARP table */
    mib[0] = CTL_NET;

    mib[1] = PF_ROUTE;

    mib[2] = 0;

    mib[3] = AF_INET;

    mib[4] = NET_RT_FLAGS;

    mib[5] = RTF_LLINFO;

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
        debugs(28, 0, "Can't estimate ARP table size!");
        return 0;
    }

    if ((buf = (char *)xmalloc(needed)) == NULL) {
        debugs(28, 0, "Can't allocate temporary ARP table!");
        return 0;
    }

    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        debugs(28, 0, "Can't retrieve ARP table!");
        xfree(buf);
        return 0;
    }

    lim = buf + needed;

    for (next = buf; next < lim; next += rtm->rtm_msglen) {

        rtm = (struct rt_msghdr *) next;

        sin = (struct sockaddr_inarp *) (rtm + 1);
        /*sdl = (struct sockaddr_dl *) (sin + 1); */

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

        sdl = (struct sockaddr_dl *)((char *) sin + ROUNDUP(sin->sin_len));

        if (c.s_addr == sin->sin_addr.s_addr) {
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
            arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0)
        return 0;

    debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
           std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

    /* Do lookup */
    *Top = (*Top)->splay((acl_arp_data *)&arpReq.arp_ha.sa_data, aclArpCompare);

    debugs(28, 3, "aclMatchArp: '" << inet_ntoa(c) << "' " << (splayLastResult ? "NOT found" : "found"));

    return (0 == splayLastResult);

#elif defined(_SQUID_WIN32_)

    DWORD           dwNetTable = 0;

    DWORD           ipNetTableLen = 0;

    PMIB_IPNETTABLE NetTable = NULL;

    DWORD            i;

    SplayNode<acl_arp_data *> **Top = dataptr;

    struct arpreq arpReq;

    memset(&arpReq, '\0', sizeof(arpReq));

    /* Get size of Windows ARP table */
    if (GetIpNetTable(NetTable, &ipNetTableLen, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        debugs(28, 0, "Can't estimate ARP table size!");
        return 0;
    }

    /* Allocate space for ARP table and assign pointers */
    if ((NetTable = (PMIB_IPNETTABLE)xmalloc(ipNetTableLen)) == NULL) {
        debugs(28, 0, "Can't allocate temporary ARP table!");
        return 0;
    }

    /* Get actual ARP table */
    if ((dwNetTable = GetIpNetTable(NetTable, &ipNetTableLen, FALSE)) != NO_ERROR) {
        debugs(28, 0, "Can't retrieve ARP table!");
        xfree(NetTable);
        return 0;
    }

    /* Find MAC address from net table */
    for (i = 0 ; i < NetTable->dwNumEntries ; i++) {
        if ((c.s_addr == NetTable->table[i].dwAddr) && (NetTable->table[i].dwType > 2)) {
            arpReq.arp_ha.sa_family = AF_UNSPEC;
            memcpy(arpReq.arp_ha.sa_data, NetTable->table[i].bPhysAddr, NetTable->table[i].dwPhysAddrLen);
        }
    }

    xfree(NetTable);

    if (arpReq.arp_ha.sa_data[0] == 0 && arpReq.arp_ha.sa_data[1] == 0 &&
            arpReq.arp_ha.sa_data[2] == 0 && arpReq.arp_ha.sa_data[3] == 0 &&
            arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0)
        return 0;

    debugs(28, 4, "Got address "<< std::setfill('0') << std::hex <<
           std::setw(2) << (arpReq.arp_ha.sa_data[0] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[1] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[2] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[3] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[4] & 0xff)  << ":" <<
           std::setw(2) << (arpReq.arp_ha.sa_data[5] & 0xff));

    /* Do lookup */
    *Top = (*Top)->splay((acl_arp_data *)&arpReq.arp_ha.sa_data, aclArpCompare);

    debugs(28, 3, "aclMatchArp: '" << inet_ntoa(c) << "' " << (splayLastResult ? "NOT found" : "found"));

    return (0 == splayLastResult);

#else

#error "ARP type ACL not supported on this operating system."

#endif
    /*
     * Address was not found on any interface
     */
    debugs(28, 3, "aclMatchArp: " << inet_ntoa(c) << " NOT found");

    return 0;
}

static int
aclArpCompare(acl_arp_data * const &a, acl_arp_data * const &b)
{
    return memcmp(a->eth, b->eth, 6);
}

static void
aclDumpArpListWalkee(acl_arp_data * const &node, void *state)
{
    acl_arp_data *arp = node;
    static char buf[24];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->eth[0] & 0xff, arp->eth[1] & 0xff,
             arp->eth[2] & 0xff, arp->eth[3] & 0xff,
             arp->eth[4] & 0xff, arp->eth[5] & 0xff);
    wordlistAdd((wordlist **)state, buf);
}

wordlist *
ACLARP::dump() const
{
    wordlist *w = NULL;
    data->walk(aclDumpArpListWalkee, &w);
    return w;
}

/* ==== END ARP ACL SUPPORT =============================================== */
