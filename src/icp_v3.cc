
/*
 * $Id: icp_v3.cc,v 1.34 2002/08/09 10:57:43 robertc Exp $
 *
 * DEBUG: section 12    Internet Cache Protocol
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
 */

#include "squid.h"

/* Currently Harvest cached-2.x uses ICP_VERSION_3 */
void
icpHandleIcpV3(int fd, struct sockaddr_in from, char *buf, int len)
{
    icp_common_t header;
    icp_common_t *reply;
    StoreEntry *entry = NULL;
    char *url = NULL;
    const cache_key *key;
    request_t *icp_request = NULL;
    int allow = 0;
    aclCheck_t checklist;
    xmemcpy(&header, buf, sizeof(icp_common_t));
    /*
     * Only these fields need to be converted
     */
    header.length = ntohs(header.length);
    header.reqnum = ntohl(header.reqnum);
    header.flags = ntohl(header.flags);
    header.pad = ntohl(header.pad);
    /*
     * Length field should match the number of bytes read
     */
    if (len != header.length) {
	debug(12, 3) ("icpHandleIcpV3: ICP message is too small\n");
	return;
    }
    switch (header.opcode) {
    case ICP_QUERY:
	/* We have a valid packet */
	url = buf + sizeof(icp_common_t) + sizeof(u_int32_t);
	if (strpbrk(url, w_space)) {
	    url = rfc1738_escape(url);
	    reply = icpCreateMessage(ICP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, 0);
	    break;
	}
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    reply = icpCreateMessage(ICP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, 0);
	    break;
	}
	memset(&checklist, '\0', sizeof(checklist));
	checklist.src_addr = from.sin_addr;
	checklist.my_addr = no_addr;
	checklist.request = icp_request;
	allow = aclCheckFast(Config.accessList.icp, &checklist);
	if (!allow) {
	    debug(12, 2) ("icpHandleIcpV3: Access Denied for %s by %s.\n",
		inet_ntoa(from.sin_addr), AclMatchedName);
	    if (clientdbCutoffDenied(from.sin_addr)) {
		/*
		 * count this DENIED query in the clientdb, even though
		 * we're not sending an ICP reply...
		 */
		clientdbUpdate(from.sin_addr, LOG_UDP_DENIED, PROTO_ICP, 0);
	    } else {
		reply = icpCreateMessage(ICP_DENIED, 0, url, header.reqnum, 0);
		icpUdpSend(fd, &from, reply, LOG_UDP_DENIED, 0);
	    }
	    break;
	}
	/* The peer is allowed to use this cache */
	entry = storeGetPublic(url, METHOD_GET);
	debug(12, 5) ("icpHandleIcpV3: OPCODE %s\n",
	    icp_opcode_str[header.opcode]);
	if (icpCheckUdpHit(entry, icp_request)) {
	    reply = icpCreateMessage(ICP_HIT, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_HIT, 0);
	    break;
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (opt_reload_hit_only && store_dirs_rebuilding) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, 0);
	} else if (hit_only_mode_until > squid_curtime) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, 0);
	} else {
	    reply = icpCreateMessage(ICP_MISS, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS, 0);
	}
	break;

    case ICP_HIT:
#if ALLOW_SOURCE_PING
    case ICP_SECHO:
#endif
    case ICP_DECHO:
    case ICP_MISS:
    case ICP_DENIED:
    case ICP_MISS_NOFETCH:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0) ("icpHandleIcpV3: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0) ("icpHandleIcpV3: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(icp_common_t);
	debug(12, 3) ("icpHandleIcpV3: %s from %s for '%s'\n",
	    icp_opcode_str[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	key = icpGetCacheKey(url, (int) header.reqnum);
	/* call neighborsUdpAck even if ping_status != PING_WAITING */
	neighborsUdpAck(key, &header, &from);
	break;

    case ICP_INVALID:
    case ICP_ERR:
	break;

    default:
	debug(12, 0) ("icpHandleIcpV3: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
    if (icp_request)
	requestDestroy(icp_request);
}
