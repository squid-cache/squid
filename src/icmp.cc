
/*
 * $Id: icmp.cc,v 1.60 1998/07/20 17:19:46 wessels Exp $
 *
 * DEBUG: section 37    ICMP Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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

#if USE_ICMP

#define S_ICMP_ECHO	1
#define S_ICMP_ICP	2
#define S_ICMP_DOM	3

static PF icmpRecv;
static void icmpSend(pingerEchoData * pkt, int len);
static void icmpHandleSourcePing(const struct sockaddr_in *from, const char *buf);

static void
icmpSendEcho(struct in_addr to, int opcode, const char *payload, int len)
{
    static pingerEchoData pecho;
    if (payload && len == 0)
	len = strlen(payload);
    pecho.to = to;
    pecho.opcode = (unsigned char) opcode;
    pecho.psize = len;
    xmemcpy(pecho.payload, payload, len);
    icmpSend(&pecho, sizeof(pingerEchoData) - PINGER_PAYLOAD_SZ + len);
}

static void
icmpRecv(int unused1, void *unused2)
{
    int n;
    static int fail_count = 0;
    pingerReplyData preply;
    static struct sockaddr_in F;
    commSetSelect(icmp_sock, COMM_SELECT_READ, icmpRecv, NULL, 0);
    memset(&preply, '\0', sizeof(pingerReplyData));
    n = recv(icmp_sock,
	(char *) &preply,
	sizeof(pingerReplyData),
	0);
    if (n < 0) {
	debug(50, 0) ("icmpRecv: recv: %s\n", xstrerror());
	if (++fail_count == 10 || errno == ECONNREFUSED)
	    icmpClose();
	return;
    }
    fail_count = 0;
    if (n == 0)			/* test probe from pinger */
	return;
    F.sin_family = AF_INET;
    F.sin_addr = preply.from;
    F.sin_port = 0;
    switch (preply.opcode) {
    case S_ICMP_ECHO:
	break;
    case S_ICMP_ICP:
	icmpHandleSourcePing(&F, preply.payload);
	break;
    case S_ICMP_DOM:
	netdbHandlePingReply(&F, preply.hops, preply.rtt);
	break;
    default:
	debug(37, 0) ("icmpRecv: Bad opcode: %d\n", (int) preply.opcode);
	break;
    }
}

static void
icmpSend(pingerEchoData * pkt, int len)
{
    int x;
    if (icmp_sock < 0)
	return;
    x = send(icmp_sock, pkt, len, 0);
    if (x < 0) {
	debug(50, 1) ("icmpSend: send: %s\n", xstrerror());
	if (errno == ECONNREFUSED) {
	    icmpClose();
	    return;
	}
    } else if (x != len) {
	debug(37, 1) ("icmpSend: Wrote %d of %d bytes\n", x, len);
    }
}

static void
icmpHandleSourcePing(const struct sockaddr_in *from, const char *buf)
{
    const cache_key *key;
    icp_common_t header;
    const char *url;
    xmemcpy(&header, buf, sizeof(icp_common_t));
    url = buf + sizeof(icp_common_t);
    if (neighbors_do_private_keys && header.reqnum) {
	key = storeKeyPrivate(url, METHOD_GET, header.reqnum);
    } else {
	key = storeKeyPublic(url, METHOD_GET);
    }
    debug(37, 3) ("icmpHandleSourcePing: from %s, key '%s'\n",
	inet_ntoa(from->sin_addr), storeKeyText(key));
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(key, &header, from);
}
#endif /* USE_ICMP */

void
icmpPing(struct in_addr to)
{
#if USE_ICMP
    icmpSendEcho(to, S_ICMP_ECHO, NULL, 0);
#endif
}

void
icmpSourcePing(struct in_addr to, const icp_common_t * header, const char *url)
{
#if USE_ICMP
    char *payload;
    int len;
    int ulen;
    debug(37, 3) ("icmpSourcePing: '%s'\n", url);
    if ((ulen = strlen(url)) > MAX_URL)
	return;
    payload = memAllocate(MEM_8K_BUF);
    len = sizeof(icp_common_t);
    xmemcpy(payload, header, len);
    strcpy(payload + len, url);
    len += ulen + 1;
    icmpSendEcho(to, S_ICMP_ICP, payload, len);
    memFree(MEM_8K_BUF, payload);
#endif
}

void
icmpDomainPing(struct in_addr to, const char *domain)
{
#if USE_ICMP
    debug(37, 3) ("icmpDomainPing: '%s'\n", domain);
    icmpSendEcho(to, S_ICMP_DOM, domain, 0);
#endif
}

void
icmpOpen(void)
{
#if USE_ICMP
    char *args[2];
    int x;
    int rfd;
    int wfd;
    args[0] = "(pinger)";
    args[1] = NULL;
    x = ipcCreate(IPC_UDP_SOCKET,
	Config.Program.pinger,
	args,
	"Pinger Socket",
	&rfd,
	&wfd);
    if (x < 0)
	return;
    assert(rfd == wfd);
    icmp_sock = rfd;
    commSetSelect(icmp_sock, COMM_SELECT_READ, icmpRecv, NULL, 0);
    commSetTimeout(icmp_sock, -1, NULL, NULL);
    debug(29, 0) ("Pinger socket opened on FD %d\n", icmp_sock);
#endif
}

void
icmpClose(void)
{
#if USE_ICMP
    if (icmp_sock < 0)
	return;
    debug(29, 0) ("Closing Pinger socket on FD %d\n", icmp_sock);
    comm_close(icmp_sock);
    icmp_sock = -1;
#endif
}
