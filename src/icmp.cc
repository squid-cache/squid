
/*
 * $Id: icmp.cc,v 1.56 1998/03/03 00:31:08 rousskov Exp $
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */


#include "squid.h"

#if USE_ICMP

#define S_ICMP_ECHO	1
#define S_ICMP_ICP	2
#define S_ICMP_DOM	3

typedef struct _icmpQueueData {
    char *msg;
    int len;
    struct _icmpQueueData *next;
    void (*free_func) (void *);
} icmpQueueData;

static icmpQueueData *IcmpQueueHead = NULL;

static PF icmpRecv;
static void icmpQueueSend(pingerEchoData * pkt, int len, FREE * free_func);
static PF icmpSend;
static void icmpHandleSourcePing(const struct sockaddr_in *from, const char *buf);

static void
icmpSendEcho(struct in_addr to, int opcode, const char *payload, int len)
{
    pingerEchoData *pecho = xcalloc(1, sizeof(pingerEchoData));
    if (payload && len == 0)
	len = strlen(payload);
    pecho->to = to;
    pecho->opcode = (unsigned char) opcode;
    pecho->psize = len;
    xmemcpy(pecho->payload, payload, len);
    icmpQueueSend(pecho, sizeof(pingerEchoData) - 8192 + len, xfree);
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
icmpQueueSend(pingerEchoData * pkt, int len, FREE * free_func)
{
    icmpQueueData *q = NULL;
    icmpQueueData **H = NULL;
    if (icmp_sock < 0) {
	if (free_func)
	    free_func(pkt);
	return;
    }
    debug(37, 3) ("icmpQueueSend: Queueing %d bytes\n", len);
    q = xcalloc(1, sizeof(icmpQueueData));
    q->msg = (char *) pkt;
    q->len = len;
    q->free_func = free_func;
    for (H = &IcmpQueueHead; *H; H = &(*H)->next);
    *H = q;
    commSetSelect(icmp_sock, COMM_SELECT_WRITE, icmpSend, IcmpQueueHead, 0);
}

static void
icmpSend(int fd, void *data)
{
    icmpQueueData *queue = data;
    int x;
    while ((queue = IcmpQueueHead) != NULL) {
	x = send(icmp_sock,
	    queue->msg,
	    queue->len,
	    0);
	if (x < 0) {
	    if (ignoreErrno(errno))
		break;		/* don't de-queue */
	    debug(50, 0) ("icmpSend: send: %s\n", xstrerror());
	    if (errno == ECONNREFUSED) {
		icmpClose();
		return;
	    }
	} else if (x != queue->len) {
	    debug(37, 0) ("icmpSend: Wrote %d of %d bytes\n", x, queue->len);
	}
	IcmpQueueHead = queue->next;
	if (queue->free_func)
	    queue->free_func(queue->msg);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (IcmpQueueHead) {
	commSetSelect(fd, COMM_SELECT_WRITE, icmpSend, IcmpQueueHead, 0);
    } else {
	commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    }
}

static void
icmpHandleSourcePing(const struct sockaddr_in *from, const char *buf)
{
    const cache_key *key;
    StoreEntry *entry;
    icp_common_t header;
    const char *url;
    xmemcpy(&header, buf, sizeof(icp_common_t));
    url = buf + sizeof(icp_common_t);
    if (neighbors_do_private_keys && header.reqnum) {
	key = storeKeyPrivate(url, METHOD_GET, header.reqnum);
    } else {
	key = storeKeyPublic(url, METHOD_GET);
    }
    debug(37, 3) ("icmpHandleSourcePing: from %s, key=%s\n",
	inet_ntoa(from->sin_addr),
	key);
    if ((entry = storeGet(key)) == NULL)
	return;
    if (entry->lock_count == 0)
	return;
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(url, &header, from, entry);
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
    icmpQueueData *queue;
    if (icmp_sock < 0)
	return;
    debug(29, 0) ("Closing Pinger socket on FD %d\n", icmp_sock);
    comm_close(icmp_sock);
    icmp_sock = -1;
    while ((queue = IcmpQueueHead) != NULL) {
	IcmpQueueHead = queue->next;
	if (queue->free_func)
	    queue->free_func(queue->msg);
	safe_free(queue);
    }
#endif
}
