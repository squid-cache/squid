
/*
 * $Id: IPInterception.cc,v 1.18 2007/11/07 10:20:47 amosjeffries Exp $
 *
 * DEBUG: section 89    NAT / IP Interception 
 * AUTHOR: Robert Collins
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
#include "clientStream.h"
#include "IPInterception.h"
#include "SquidTime.h"

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
#endif

#if PF_TRANSPARENT
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#endif

#if LINUX_NETFILTER
#include <linux/netfilter_ipv4.h>
#endif

#if IPF_TRANSPARENT
int

clientNatLookup(int fd, struct sockaddr_in me, struct sockaddr_in peer, struct sockaddr_in *dst)
{

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)

    struct ipfobj obj;
#else

    static int siocgnatl_cmd = SIOCGNATL & 0xff;

#endif

    struct natlookup natLookup;
    static int natfd = -1;
    static time_t last_reported = 0;
    int x;

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)

    obj.ipfo_rev = IPFILTER_VERSION;
    obj.ipfo_size = sizeof(natLookup);
    obj.ipfo_ptr = &natLookup;
    obj.ipfo_type = IPFOBJ_NATLOOKUP;
    obj.ipfo_offset = 0;
#endif

    natLookup.nl_inport = me.sin_port;
    natLookup.nl_outport = peer.sin_port;
    natLookup.nl_inip = me.sin_addr;
    natLookup.nl_outip = peer.sin_addr;
    natLookup.nl_flags = IPN_TCP;

    if (natfd < 0)
    {
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

    if (natfd < 0)
    {
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
    if (63 == siocgnatl_cmd)
    {

        struct natlookup *nlp = &natLookup;
        x = ioctl(natfd, SIOCGNATL, &nlp);
    } else
    {
        x = ioctl(natfd, SIOCGNATL, &natLookup);
    }

#endif
    if (x < 0)
    {
        if (errno != ESRCH) {
            if (squid_curtime - last_reported > 60) {
                debugs(89, 1, "clientNatLookup: NAT lookup failed: ioctl(SIOCGNATL)");
                last_reported = squid_curtime;
            }

            close(natfd);
            natfd = -1;
        }

        return -1;
    } else
    {
        if (me.sin_addr.s_addr != natLookup.nl_realip.s_addr)
            dst->sin_family = AF_INET;

        dst->sin_port = natLookup.nl_realport;

        dst->sin_addr = natLookup.nl_realip;

        return 0;
    }
}

#elif LINUX_NETFILTER
int

clientNatLookup(int fd, struct sockaddr_in me, struct sockaddr_in peer, struct sockaddr_in *dst)
{
    static time_t last_reported = 0;
    socklen_t sock_sz = sizeof(*dst);
    memcpy(dst, &me, sizeof(*dst));

    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, dst, &sock_sz) != 0)
    {
        if (squid_curtime - last_reported > 60) {
            debugs(89, 1, "clientNatLookup: NF getsockopt(SO_ORIGINAL_DST) failed: " << xstrerror());
            last_reported = squid_curtime;
        }

        return -1;
    }

    debugs(89, 5, "clientNatLookup: addr = " << inet_ntoa(dst->sin_addr) << "");

    if (me.sin_addr.s_addr != dst->sin_addr.s_addr)
        return 0;
    else
        return -1;
}

#elif PF_TRANSPARENT
int

clientNatLookup(int fd, struct sockaddr_in me, struct sockaddr_in peer, struct sockaddr_in *dst)
{

    struct pfioc_natlook nl;
    static int pffd = -1;
    static time_t last_reported = 0;

    if (pffd < 0)
        pffd = open("/dev/pf", O_RDWR);

    if (pffd < 0)
    {
        if (squid_curtime - last_reported > 60) {
            debugs(89, 1, "clientNatLookup: PF open failed: " << xstrerror());
            last_reported = squid_curtime;
        }

        return -1;

    }

    memset(dst, 0, sizeof(*dst));

    memset(&nl, 0, sizeof(struct pfioc_natlook));
    nl.saddr.v4.s_addr = peer.sin_addr.s_addr;
    nl.sport = peer.sin_port;
    nl.daddr.v4.s_addr = me.sin_addr.s_addr;
    nl.dport = me.sin_port;
    nl.af = AF_INET;
    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;

    if (ioctl(pffd, DIOCNATLOOK, &nl))
    {
        if (errno != ENOENT) {
            if (squid_curtime - last_reported > 60) {
                debugs(89, 1, "clientNatLookup: PF lookup failed: ioctl(DIOCNATLOOK)");
                last_reported = squid_curtime;
            }

            close(pffd);
            pffd = -1;
        }

        return -1;
    } else
    {
        int natted = me.sin_addr.s_addr != nl.rdaddr.v4.s_addr;
        dst->sin_family = AF_INET;
        dst->sin_port = nl.rdport;
        dst->sin_addr = nl.rdaddr.v4;

        if (natted)
            return 0;
        else
            return -1;
    }
}

#elif IPFW_TRANSPARENT
int
clientNatLookup(int fd, struct sockaddr_in me, struct sockaddr_in peer, struct sockaddr_in *dst)
{
	int ret;
	struct sockaddr_in s;
	int slen = sizeof(struct sockaddr_in);

	ret = getsockname(fd, (struct sockaddr *) &s, (socklen_t * )&slen);
	if (ret < 0) {
		debugs(89, 1, "clientNatLookup: getpeername failed (fd " << fd << "), errstr " << xstrerror());
		return -1;
	}
	*dst = s;
	return 0;
}

#else
int
clientNatLookup(int fd, struct sockaddr_in me, struct sockaddr_in peer, struct sockaddr_in *dst)
{
	debugs(89, 1, "WARNING: transparent proxying not supported");
	return -1;
}
#endif

