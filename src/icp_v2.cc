
#include "squid.h"

static void icpLogIcp(struct in_addr, log_type, int, const char *, int);
static void icpHandleIcpV2(int, struct sockaddr_in, char *, int);
static PF icpUdpSendQueue;
static void icpCount(void *, int, size_t, int);

static icpUdpData *UdpQueueHead = NULL;
static icpUdpData *UdpQueueTail = NULL;

static void
icpLogIcp(struct in_addr caddr, log_type logcode, int len, const char *url, int delay)
{
    AccessLogEntry al;
    if (LOG_TAG_NONE == logcode)
	return;
    if (LOG_ICP_QUERY == logcode)
	return;
    clientdbUpdate(caddr, logcode, PROTO_ICP, len);
    if (!Config.onoff.log_udp)
	return;
    memset(&al, '\0', sizeof(al));
    al.icp.opcode = ICP_QUERY;
    al.url = url;
    al.cache.caddr = caddr;
    al.cache.size = len;
    al.cache.code = logcode;
    al.cache.msec = delay;
    accessLogLog(&al);
}

static void
icpUdpSendQueue(int fd, void *unused)
{
    icpUdpData *q;
    int x;
    int delay;
    while ((q = UdpQueueHead) != NULL) {
	delay = tvSubUsec(q->queue_time, current_time);
	/* increment delay to prevent looping */
	x = icpUdpSend(fd, &q->address, q->msg, q->logcode, ++delay);
	UdpQueueHead = q->next;
	safe_free(q);
	if (x < 0)
	    break;
    }
}

void *
icpCreateMessage(
    icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad)
{
    char *buf = NULL;
    icp_common_t *headerp = NULL;
    char *urloffset = NULL;
    int buf_len;
    buf_len = sizeof(icp_common_t) + strlen(url) + 1;
    if (opcode == ICP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = (char) opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = (u_short) htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    headerp->flags = htonl(flags);
    headerp->pad = htonl(pad);
    headerp->shostid = theOutICPAddr.s_addr;
    urloffset = buf + sizeof(icp_common_t);
    if (opcode == ICP_QUERY)
	urloffset += sizeof(u_num32);
    xmemcpy(urloffset, url, strlen(url));
    return buf;
}

int
icpUdpSend(int fd,
    const struct sockaddr_in *to,
    icp_common_t * msg,
    log_type logcode,
    int delay)
{
    icpUdpData *queue;
    int x;
    int len;
    len = (int) ntohs(msg->length);
    debug(12, 5) ("icpUdpSend: FD %d sending %s, %d bytes to %s:%d\n",
	fd,
	icp_opcode_str[msg->opcode],
	len,
	inet_ntoa(to->sin_addr),
	ntohs(to->sin_port));
    x = comm_udp_sendto(fd, to, sizeof(*to), msg, len);
    if (x >= 0) {
	/* successfully written */
	icpLogIcp(to->sin_addr, logcode, len, (char *) (msg + 1), delay);
	icpCount(msg, SENT, (size_t) len, delay);
	safe_free(msg);
    } else if (0 == delay) {
	/* send failed, but queue it */
	queue = xcalloc(1, sizeof(icpUdpData));
	queue->address = *to;
	queue->msg = msg;
	queue->len = (int) ntohs(msg->length);
	queue->queue_time = current_time;
	queue->logcode = logcode;
	if (UdpQueueHead == NULL) {
	    UdpQueueHead = queue;
	    UdpQueueTail = queue;
	} else if (UdpQueueTail == UdpQueueHead) {
	    UdpQueueTail = queue;
	    UdpQueueHead->next = queue;
	} else {
	    UdpQueueTail->next = queue;
	    UdpQueueTail = queue;
	}
	commSetSelect(fd, COMM_SELECT_WRITE, icpUdpSendQueue, NULL, 0);
	Counter.icp.replies_queued++;
    } else {
	/* don't queue it */
	Counter.icp.replies_dropped++;
    }
    return x;
}

int
icpCheckUdpHit(StoreEntry * e, request_t * request)
{
    if (e == NULL)
	return 0;
    if (!storeEntryValidToSend(e))
	return 0;
    if (Config.onoff.icp_hit_stale)
	return 1;
    if (refreshCheck(e, request, 30))
	return 0;
    return 1;
}

static void
icpHandleIcpV2(int fd, struct sockaddr_in from, char *buf, int len)
{
    icp_common_t header;
    StoreEntry *entry = NULL;
    char *url = NULL;
    const cache_key *key;
    request_t *icp_request = NULL;
    int allow = 0;
    aclCheck_t checklist;
    icp_common_t *reply;
    int src_rtt = 0;
    u_num32 flags = 0;
    method_t method;
    int rtt = 0;
    int hops = 0;
    xmemcpy(&header, buf, sizeof(icp_common_t));
    /*
     * Only these fields need to be converted
     */
    header.length = ntohs(header.length);
    header.reqnum = ntohl(header.reqnum);
    header.flags = ntohl(header.flags);
    header.pad = ntohl(header.pad);

    method = header.reqnum >> 24;
    /* Squid-1.1 doesn't use the "method bits" for METHOD_GET */
    if (METHOD_NONE == method || METHOD_ENUM_END <= method)
	method = METHOD_GET;
    switch (header.opcode) {
    case ICP_QUERY:
	/* We have a valid packet */
	url = buf + sizeof(icp_common_t) + sizeof(u_num32);
	if ((icp_request = urlParse(method, url)) == NULL) {
	    reply = icpCreateMessage(ICP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, 0);
	    break;
	}
	checklist.src_addr = from.sin_addr;
	checklist.request = icp_request;
	allow = aclCheckFast(Config.accessList.icp, &checklist);
	if (!allow) {
	    debug(12, 2) ("icpHandleIcpV2: Access Denied for %s by %s.\n",
		inet_ntoa(from.sin_addr), AclMatchedName);
	    if (clientdbCutoffDenied(from.sin_addr)) {
		/*
		 * count this DENIED query in the clientdb, even though
		 * we're not sending an ICP reply...
		 */
		clientdbUpdate(from.sin_addr, LOG_UDP_DENIED, Config.Port.icp, 0);
	    } else {
		reply = icpCreateMessage(ICP_DENIED, 0, url, header.reqnum, 0);
		icpUdpSend(fd, &from, reply, LOG_UDP_DENIED, 0);
	    }
	    break;
	}
	if (header.flags & ICP_FLAG_SRC_RTT) {
	    rtt = netdbHostRtt(icp_request->host);
	    hops = netdbHostHops(icp_request->host);
	    src_rtt = ((hops & 0xFFFF) << 16) | (rtt & 0xFFFF);
	    if (rtt)
		flags |= ICP_FLAG_SRC_RTT;
	}
	/* The peer is allowed to use this cache */
	key = storeKeyPublic(url, method);
	entry = storeGet(key);
	debug(12, 5) ("icpHandleIcpV2: OPCODE %s\n", icp_opcode_str[header.opcode]);
	if (icpCheckUdpHit(entry, icp_request)) {
	    reply = icpCreateMessage(ICP_HIT, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_HIT, 0);
	    break;
	}
	if (Config.onoff.test_reachability && rtt == 0) {
	    if ((rtt = netdbHostRtt(icp_request->host)) == 0)
		netdbPingSite(icp_request->host);
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (store_rebuilding && opt_reload_hit_only) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, 0);
	} else if (hit_only_mode_until > squid_curtime) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, 0);
	} else if (Config.onoff.test_reachability && rtt == 0) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, 0);
	} else {
	    reply = icpCreateMessage(ICP_MISS, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS, 0);
	}
	break;

    case ICP_HIT:
    case ICP_SECHO:
    case ICP_DECHO:
    case ICP_MISS:
    case ICP_DENIED:
    case ICP_MISS_NOFETCH:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0) ("icpHandleIcpV2: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0) ("icpHandleIcpV2: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(icp_common_t);
	debug(12, 3) ("icpHandleIcpV2: %s from %s for '%s'\n",
	    icp_opcode_str[header.opcode],
	    inet_ntoa(from.sin_addr),
	    url);
	if (neighbors_do_private_keys && header.reqnum)
	    key = storeKeyPrivate(url, method, header.reqnum);
	else
	    key = storeKeyPublic(url, method);
	/* call neighborsUdpAck even if ping_status != PING_WAITING */
	neighborsUdpAck(key, &header, &from);
	break;

    case ICP_INVALID:
    case ICP_ERR:
	break;

    default:
	debug(12, 0) ("icpHandleIcpV2: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
    if (icp_request) {
#if OLD_CODE
	stringClean(&icp_request->urlpath);
	memFree(MEM_REQUEST_T, icp_request);
#else
	requestDestroy(icp_request);
#endif
    }
}

#ifdef ICP_PKT_DUMP
static void
icpPktDump(icp_common_t * pkt)
{
    struct in_addr a;

    debug(12, 9) ("opcode:     %3d %s\n",
	(int) pkt->opcode,
	icp_opcode_str[pkt->opcode]);
    debug(12, 9) ("version: %-8d\n", (int) pkt->version);
    debug(12, 9) ("length:  %-8d\n", (int) ntohs(pkt->length));
    debug(12, 9) ("reqnum:  %-8d\n", ntohl(pkt->reqnum));
    debug(12, 9) ("flags:   %-8x\n", ntohl(pkt->flags));
    a.s_addr = pkt->shostid;
    debug(12, 9) ("shostid: %s\n", inet_ntoa(a));
    debug(12, 9) ("payload: %s\n", (char *) pkt + sizeof(icp_common_t));
}
#endif

void
icpHandleUdp(int sock, void *data)
{
    int *N = data;
    struct sockaddr_in from;
    int from_len;
    LOCAL_ARRAY(char, buf, SQUID_UDP_SO_RCVBUF);
    int len;
    int icp_version;
    int max = INCOMING_ICP_MAX;
    commSetSelect(sock, COMM_SELECT_READ, icpHandleUdp, NULL, 0);
    while (max--) {
	from_len = sizeof(from);
	memset(&from, '\0', from_len);
	len = recvfrom(sock,
	    buf,
	    SQUID_UDP_SO_RCVBUF - 1,
	    0,
	    (struct sockaddr *) &from,
	    &from_len);
	if (len == 0)
	    break;
	if (len < 0) {
	    if (ignoreErrno(errno))
		break;
#ifdef _SQUID_LINUX_
	    /* Some Linux systems seem to set the FD for reading and then
	     * return ECONNREFUSED when sendto() fails and generates an ICMP
	     * port unreachable message. */
	    /* or maybe an EHOSTUNREACH "No route to host" message */
	    if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif
		debug(50, 1) ("icpHandleUdp: FD %d recvfrom: %s\n",
		    sock, xstrerror());
	    break;
	}
	(*N)++;
	icpCount(buf, RECV, (size_t) len, 0);
	buf[len] = '\0';
	debug(12, 4) ("icpHandleUdp: FD %d: received %d bytes from %s.\n",
	    sock,
	    len,
	    inet_ntoa(from.sin_addr));
#ifdef ICP_PACKET_DUMP
	icpPktDump(buf);
#endif
	if (len < sizeof(icp_common_t)) {
	    debug(12, 4) ("icpHandleUdp: Ignoring too-small UDP packet\n");
	    break;
	}
	icp_version = (int) buf[1];	/* cheat! */
	if (icp_version == ICP_VERSION_2)
	    icpHandleIcpV2(sock, from, buf, len);
	else if (icp_version == ICP_VERSION_3)
	    icpHandleIcpV3(sock, from, buf, len);
	else
	    debug(12, 0) ("WARNING: Unused ICP version %d received from %s:%d\n",
		icp_version,
		inet_ntoa(from.sin_addr),
		ntohs(from.sin_port));
    }
}

void
icpConnectionsOpen(void)
{
    u_short port;
    struct in_addr addr;
    struct sockaddr_in xaddr;
    int x;
    int len;
    wordlist *s;
    if (Config2.Accel.on && !Config.onoff.accel_with_proxy)
	return;
    if ((port = Config.Port.icp) <= 0)
	return;
    enter_suid();
    theInIcpConnection = comm_open(SOCK_DGRAM,
	0,
	Config.Addrs.udp_incoming,
	port,
	COMM_NONBLOCKING,
	"ICP Socket");
    leave_suid();
    if (theInIcpConnection < 0)
	fatal("Cannot open ICP Port");
    commSetSelect(theInIcpConnection,
	COMM_SELECT_READ,
	icpHandleUdp,
	NULL,
	0);
    for (s = Config.mcast_group_list; s; s = s->next)
	ipcache_nbgethostbyname(s->key, mcastJoinGroups, NULL);
    debug(12, 1) ("Accepting ICP messages on port %d, FD %d.\n",
	(int) port, theInIcpConnection);
    if ((addr = Config.Addrs.udp_outgoing).s_addr != no_addr.s_addr) {
	enter_suid();
	theOutIcpConnection = comm_open(SOCK_DGRAM,
	    0,
	    addr,
	    port,
	    COMM_NONBLOCKING,
	    "ICP Port");
	leave_suid();
	if (theOutIcpConnection < 0)
	    fatal("Cannot open Outgoing ICP Port");
	commSetSelect(theOutIcpConnection,
	    COMM_SELECT_READ,
	    icpHandleUdp,
	    NULL,
	    0);
	debug(12, 1) ("Outgoing ICP messages on port %d, FD %d.\n",
	    (int) port, theOutIcpConnection);
	fd_note(theOutIcpConnection, "Outgoing ICP socket");
	fd_note(theInIcpConnection, "Incoming ICP socket");
    } else {
	theOutIcpConnection = theInIcpConnection;
    }
    memset(&theOutICPAddr, '\0', sizeof(struct in_addr));
    len = sizeof(struct sockaddr_in);
    memset(&xaddr, '\0', len);
    x = getsockname(theOutIcpConnection,
	(struct sockaddr *) &xaddr, &len);
    if (x < 0)
	debug(50, 1) ("theOutIcpConnection FD %d: getsockname: %s\n",
	    theOutIcpConnection, xstrerror());
    else
	theOutICPAddr = xaddr.sin_addr;
}

/*
 * icpConnectionShutdown only closes the 'in' socket if it is 
 * different than the 'out' socket.
 */
void
icpConnectionShutdown(void)
{
    if (theInIcpConnection < 0)
	return;
    if (theInIcpConnection != theOutIcpConnection) {
	debug(12, 1) ("FD %d Closing ICP connection\n", theInIcpConnection);
	comm_close(theInIcpConnection);
    }
    /*
     * Here we set 'theInIcpConnection' to -1 even though the ICP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */
    theInIcpConnection = -1;
    /*
     * Normally we only write to the outgoing ICP socket, but
     * we also have a read handler there to catch messages sent
     * to that specific interface.  During shutdown, we must
     * disable reading on the outgoing socket.
     */
    assert(theOutIcpConnection > -1);
    commSetSelect(theOutIcpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}

void
icpConnectionClose(void)
{
    icpConnectionShutdown();
    if (theOutIcpConnection > -1) {
	debug(12, 1) ("FD %d Closing ICP connection\n", theOutIcpConnection);
	comm_close(theOutIcpConnection);
    }
}

static void
icpCount(void *buf, int which, size_t len, int delay)
{
    icp_common_t *icp = buf;
    if (len < sizeof(*icp))
	return;
    if (SENT == which) {
	Counter.icp.pkts_sent++;
	kb_incr(&Counter.icp.kbytes_sent, len);
	if (ICP_QUERY == icp->opcode) {
	    Counter.icp.queries_sent++;
	    kb_incr(&Counter.icp.q_kbytes_sent, len);
	} else {
	    Counter.icp.replies_sent++;
	    kb_incr(&Counter.icp.r_kbytes_sent, len);
	    /* this is the sent-reply service time */
	    statHistCount(&Counter.icp.reply_svc_time, delay);
	}
	if (ICP_HIT == icp->opcode)
	    Counter.icp.hits_sent++;
    } else if (RECV == which) {
	Counter.icp.pkts_recv++;
	kb_incr(&Counter.icp.kbytes_recv, len);
	if (ICP_QUERY == icp->opcode) {
	    Counter.icp.queries_recv++;
	    kb_incr(&Counter.icp.q_kbytes_recv, len);
	} else {
	    Counter.icp.replies_recv++;
	    kb_incr(&Counter.icp.r_kbytes_recv, len);
	    /* Counter.icp.query_svc_time set in clientUpdateCounters */
	}
	if (ICP_HIT == icp->opcode)
	    Counter.icp.hits_recv++;
    }
}
