
/*
 * $Id: icmp.cc,v 1.19 1996/10/11 23:11:12 wessels Exp $
 *
 * DEBUG: section 37    ICMP Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#if USE_ICMP

#include "squid.h"
#include "pinger.h"

#define S_ICMP_ECHO	1
#define S_ICMP_ICP	2
#define S_ICMP_DOM	3

typedef struct _icmpQueueData {
    char *msg;
    int len;
    struct _icmpQueueData *next;
    void (*free_func) _PARAMS((void *));
} icmpQueueData;

static icmpQueueData *IcmpQueueHead = NULL;

int icmp_sock = -1;

static void icmpRecv _PARAMS((int, void *));
static void icmpQueueSend _PARAMS((pingerEchoData * pkt,
	int len,
	void          (*free_func) _PARAMS((void *))));
static void icmpSend _PARAMS((int fd, icmpQueueData * queue));
static void icmpHandleSourcePing _PARAMS((struct sockaddr_in * from, char *buf));

void
icmpOpen(void)
{
    struct sockaddr_in S;
    int namelen = sizeof(struct sockaddr_in);
    pid_t pid;
    int child_sock;
    icmp_sock = comm_open(SOCK_DGRAM,
	0,
	local_addr,
	0,
	COMM_NONBLOCKING,
	"ICMP Socket");
    if (icmp_sock < 0) {
	debug(37, 0, "icmpOpen: icmp_sock: %s\n", xstrerror());
	return;
    }
    child_sock = comm_open(SOCK_DGRAM,
	0,
	local_addr,
	0,
	0,
	"ICMP Socket");
    if (child_sock < 0) {
	debug(37, 0, "icmpOpen: child_sock: %s\n", xstrerror());
	return;
    }
    getsockname(icmp_sock, (struct sockaddr *) &S, &namelen);
    if (comm_connect_addr(child_sock, &S) != COMM_OK)
	fatal_dump(xstrerror());
    getsockname(child_sock, (struct sockaddr *) &S, &namelen);
    if (comm_connect_addr(icmp_sock, &S) != COMM_OK)
	fatal_dump(xstrerror());
    if ((pid = fork()) < 0) {
	debug(29, 0, "icmpOpen: fork: %s\n", xstrerror());
	comm_close(icmp_sock);
	comm_close(child_sock);
	return;
    }
    if (pid == 0) {		/* child */
	char *x = xcalloc(strlen(Config.debugOptions) + 32, 1);
	sprintf(x, "SQUID_DEBUG=%s\n", Config.debugOptions);
	putenv(x);
	comm_close(icmp_sock);
	dup2(child_sock, 0);
	dup2(child_sock, 1);
	comm_close(child_sock);
	dup2(fileno(debug_log), 2);
	fclose(debug_log);
	enter_suid();
	execlp(Config.Program.pinger, "(pinger)", NULL);
	debug(29, 0, "icmpOpen: %s: %s\n", Config.Program.pinger, xstrerror());
	_exit(1);
    }
    comm_close(child_sock);
    commSetSelect(icmp_sock,
	COMM_SELECT_READ,
	(PF) icmpRecv,
	(void *) -1, 0);
    comm_set_fd_lifetime(icmp_sock, -1);
    debug(29,0,"Pinger socket opened on FD %d\n", icmp_sock);
}

void
icmpClose(void)
{
    icmpQueueData *queue;
    debug(29, 0, "Closing ICMP socket on FD %d\n", icmp_sock);
    comm_close(icmp_sock);
    commSetSelect(icmp_sock,
	COMM_SELECT_READ,
	NULL,
	NULL, 0);
    icmp_sock = -1;
    while ((queue = IcmpQueueHead)) {
	IcmpQueueHead = queue->next;
	if (queue->free_func)
	    queue->free_func(queue->msg);
	safe_free(queue);
    }
}

static void
icmpSendEcho(struct in_addr to, int opcode, char *payload, int len)
{
    pingerEchoData *pecho = xcalloc(1, sizeof(pingerEchoData));
    if (payload && len == 0)
	len = strlen(payload);
    pecho->to = to;
    pecho->opcode = (unsigned char) opcode;
    pecho->psize = len;
    memcpy(pecho->payload, payload, len);
    icmpQueueSend(pecho, sizeof(pingerEchoData) - 8192 + len, xfree);
}

static void
icmpRecv(int unused1, void *unused2)
{
    int n;
    pingerReplyData preply;
    static struct sockaddr_in F;

    commSetSelect(icmp_sock,
	COMM_SELECT_READ,
	(PF) icmpRecv,
	(void *) -1, 0);
    memset((char *) &preply, '\0', sizeof(pingerReplyData));
    n = recv(icmp_sock,
	(char *) &preply,
	sizeof(pingerReplyData),
	0);
    if (n < 0) {
	debug(37, 0, "icmpRecv: recv: %s\n", xstrerror());
	return;
    }
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
	debug(37, 0, "icmpRecv: Bad opcode: %d\n", (int) preply.opcode);
	break;
    }
}


static void
icmpQueueSend(pingerEchoData * pkt,
    int len,
    void (*free_func) _PARAMS((void *)))
{
    icmpQueueData *q = NULL;
    icmpQueueData **H = NULL;
    if (icmp_sock < 0) {
	if (free_func)
	    free_func(pkt);
	return;
    }
    debug(37, 3, "icmpQueueSend: Queueing %d bytes\n", len);
    q = xcalloc(1, sizeof(icmpQueueData));
    q->msg = (char *) pkt;
    q->len = len;
    q->free_func = free_func;
    for (H = &IcmpQueueHead; *H; H = &(*H)->next);
    *H = q;
    commSetSelect(icmp_sock,
	COMM_SELECT_WRITE,
	(PF) icmpSend,
	(void *) IcmpQueueHead, 0);
}

static void
icmpSend(int fd, icmpQueueData * queue)
{
    int x;
    while ((queue = IcmpQueueHead)) {
	x = send(icmp_sock,
	    queue->msg,
	    queue->len,
	    0);
	if (x < 0) {
	    if (errno == EWOULDBLOCK || errno == EAGAIN)
		break;		/* don't de-queue */
	    else
		debug(37, 0, "icmpSend: send: %s\n", xstrerror());
	} else if (x != queue->len) {
	    debug(37, 0, "icmpSend: Wrote %d of %d bytes\n", x, queue->len);
	}
	IcmpQueueHead = queue->next;
	if (queue->free_func)
	    queue->free_func(queue->msg);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (IcmpQueueHead) {
	commSetSelect(fd,
	    COMM_SELECT_WRITE,
	    (PF) icmpSend,
	    (void *) IcmpQueueHead, 0);
    } else {
	commSetSelect(fd,
	    COMM_SELECT_WRITE,
	    NULL,
	    NULL, 0);
    }
}

void
icmpPing(struct in_addr to)
{
    icmpSendEcho(to, S_ICMP_ECHO, NULL, 0);
}

void
icmpSourcePing(struct in_addr to, icp_common_t * header, char *url)
{
    char *payload;
    int len;
    int ulen;
    debug(37, 3, "icmpSourcePing: '%s'\n", url);
    if ((ulen = strlen(url)) > MAX_URL)
	return;
    payload = get_free_8k_page();
    len = sizeof(icp_common_t);
    memcpy(payload, header, len);
    strcpy(payload + len, url);
    len += ulen + 1;
    icmpSendEcho(to, S_ICMP_ICP, payload, len);
    put_free_8k_page(payload);
}

void
icmpDomainPing(struct in_addr to, char *domain)
{
    debug(37, 3, "icmpDomainPing: '%s'\n", domain);
    icmpSendEcho(to, S_ICMP_DOM, domain, 0);
}

static void
icmpHandleSourcePing(struct sockaddr_in *from, char *buf)
{
    char *key;
    StoreEntry *entry;
    icp_common_t header;
    char *url;
    memcpy(&header, buf, sizeof(icp_common_t));
    url = buf + sizeof(icp_common_t);
    if (neighbors_do_private_keys && header.reqnum) {
	key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
    } else {
	key = storeGeneratePublicKey(url, METHOD_GET);
    }
    debug(37, 3, "icmpHandleSourcePing: from %s, key=%s\n",
	inet_ntoa(from->sin_addr),
	key);
    if ((entry = storeGet(key)) == NULL)
	return;
    if (entry->lock_count == 0)
	return;
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(icmp_sock,
	url,
	&header,
	from,
	entry,
	NULL,
	0);
}

#endif /* USE_ICMP */
