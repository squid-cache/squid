
/*
 * $Id: IPInterception.cc,v 1.2 2002/09/24 11:56:50 robertc Exp $
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

#if IPF_TRANSPARENT
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <netinet/tcp.h>
#include <net/if.h>
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

void
rewriteURIwithInterceptedDetails(char const *originalURL, char *uriBuffer, size_t bufferLength, struct sockaddr_in me, struct sockaddr_in peer, int vport)
{
#if IPF_TRANSPARENT
    struct natlookup natLookup;
    static int natfd = -1;
    static int siocgnatl_cmd = SIOCGNATL & 0xff;
    int x;
#endif
#if PF_TRANSPARENT
    struct pfioc_natlook nl;
    static int pffd = -1;
#endif
#if LINUX_NETFILTER
    size_t sock_sz = sizeof(conn->me);
#endif
#if IPF_TRANSPARENT
    natLookup.nl_inport = me.sin_port;
    natLookup.nl_outport = peer.sin_port;
    natLookup.nl_inip = me.sin_addr;
    natLookup.nl_outip = peer.sin_addr;
    natLookup.nl_flags = IPN_TCP;
    if (natfd < 0) {
	int save_errno;
	enter_suid();
	natfd = open(IPL_NAT, O_RDONLY, 0);
	save_errno = errno;
	leave_suid();
	errno = save_errno;
    }
    if (natfd < 0) {
	debug(89, 1) ("rewriteURIwithInterceptedDetails: NAT open failed: %s\n",
	    xstrerror());
	cbdataFree(context);
	xfree(inbuf);
	return rewriteURIwithInterceptedDetailsAbort(conn, "error:nat-open-failed");
    }
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
    if (x < 0) {
	if (errno != ESRCH) {
	    debug(89, 1) ("rewriteURIwithInterceptedDetails: NAT lookup failed: ioctl(SIOCGNATL)\n");
	    close(natfd);
	    natfd = -1;
	    cbdataFree(context);
	    xfree(inbuf);
	    return rewriteURIwithInterceptedDetailsAbort(conn,
		"error:nat-lookup-failed");
	} else
	    snprintf(uriBuffer, bufferLength, "http://%s:%d%s",
		inet_ntoa(me.sin_addr), vport, originalURL);
    } else {
	if (vport_mode)
	    vport = ntohs(natLookup.nl_realport);
	snprintf(uriBuffer, bufferLength, "http://%s:%d%s",
	    inet_ntoa(natLookup.nl_realip), vport, originalURL);
    }
#elif PF_TRANSPARENT
    if (pffd < 0)
	pffd = open("/dev/pf", O_RDWR);
    if (pffd < 0) {
	debug(89, 1) ("rewriteURIwithInterceptedDetails: PF open failed: %s\n",
	    xstrerror());
	cbdataFree(context);
	xfree(inbuf);
	return rewriteURIwithInterceptedDetailsAbort(conn, "error:pf-open-failed");
    }
    memset(&nl, 0, sizeof(struct pfioc_natlook));
    nl.saddr.v4.s_addr = peer.sin_addr.s_addr;
    nl.sport = peer.sin_port;
    nl.daddr.v4.s_addr = me.sin_addr.s_addr;
    nl.dport = me.sin_port;
    nl.af = AF_INET;
    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;
    if (ioctl(pffd, DIOCNATLOOK, &nl)) {
	if (errno != ENOENT) {
	    debug(89, 1) ("rewriteURIwithInterceptedDetails: PF lookup failed: ioctl(DIOCNATLOOK)\n");
	    close(pffd);
	    pffd = -1;
	    cbdataFree(context);
	    xfree(inbuf);
	    return rewriteURIwithInterceptedDetailsAbort(conn,
		"error:pf-lookup-failed");
	} else
	    snprintf(uriBuffer, bufferLength, "http://%s:%d%s",
		inet_ntoa(me.sin_addr), vport, originalURL);
    } else
	snprintf(uriBuffer, bufferLength, "http://%s:%d%s",
	    inet_ntoa(nl.rdaddr.v4), ntohs(nl.rdport), originalURL);
#else
#if LINUX_NETFILTER
    /* If the call fails the address structure will be unchanged */
    getsockopt(conn->fd, SOL_IP, SO_ORIGINAL_DST, &conn->me, &sock_sz);
    debug(89, 5) ("rewriteURIwithInterceptedDetails: addr = %s",
	inet_ntoa(conn->me.sin_addr));
    if (vport_mode)
	vport = (int) ntohs(me.sin_port);
#endif
    snprintf(uriBuffer, bufferLength, "http://%s:%d%s",
	inet_ntoa(me.sin_addr), vport, originalURL);
#endif
}
