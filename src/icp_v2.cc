#include "squid.h"

static void icpLogIcp(icpUdpData *);
static void icpHandleIcpV2(int, struct sockaddr_in, char *, int);

static void
icpLogIcp(icpUdpData * queue)
{
    icp_common_t *header = (icp_common_t *) (void *) queue->msg;
    char *url = (char *) header + sizeof(icp_common_t);
    AccessLogEntry al;
    clientdbUpdate(queue->address.sin_addr, queue->logcode, PROTO_ICP);
    if (!Config.onoff.log_udp)
	return;
    memset(&al, '\0', sizeof(AccessLogEntry));
    al.icp.opcode = ICP_QUERY;
    al.url = url;
    al.cache.caddr = queue->address.sin_addr;
    al.cache.size = queue->len;
    al.cache.code = queue->logcode;
    al.cache.msec = tvSubMsec(queue->start, current_time);
    accessLogLog(&al);
}

void
icpUdpReply(int fd, void *data)
{
    icpUdpData *queue = data;
    int x;
    /* Disable handler, in case of errors. */
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    while ((queue = UdpQueueHead) != NULL) {
	debug(12, 5) ("icpUdpReply: FD %d sending %d bytes to %s port %d\n",
	    fd,
	    queue->len,
	    inet_ntoa(queue->address.sin_addr),
	    ntohs(queue->address.sin_port));
	Counter.icp.pkts_sent++;
	if (queue->logcode == LOG_UDP_HIT)
	    Counter.icp.hits_sent++;
	x = comm_udp_sendto(fd,
	    &queue->address,
	    sizeof(struct sockaddr_in),
	    queue->msg,
	    queue->len);
	if (x < 0) {
	    if (ignoreErrno(errno))
		break;		/* don't de-queue */
	} else {
	    kb_incr(&Counter.icp.kbytes_sent, (size_t) x);
	}
	UdpQueueHead = queue->next;
	if (queue->logcode) {
	    icpLogIcp(queue);
	    statHistCount(&Counter.icp.reply_svc_time,
		tvSubUsec(queue->start, current_time));
	}
	safe_free(queue->msg);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (UdpQueueHead) {
	commSetSelect(fd, COMM_SELECT_WRITE, icpUdpReply, UdpQueueHead, 0);
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

void
icpUdpSend(int fd,
    const struct sockaddr_in *to,
    icp_common_t * msg,
    log_type logcode,
    protocol_t proto)
{
    icpUdpData *data = xcalloc(1, sizeof(icpUdpData));
    debug(12, 4) ("icpUdpSend: Queueing %s for %s\n",
	icp_opcode_str[msg->opcode],
	inet_ntoa(to->sin_addr));
    data->address = *to;
    data->msg = msg;
    data->len = (int) ntohs(msg->length);
    data->start = current_time;
    data->logcode = logcode;
    data->proto = proto;
    AppendUdp(data);
    commSetSelect(fd, COMM_SELECT_WRITE, icpUdpReply, UdpQueueHead, 0);
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
    xmemcpy(&header, buf, sizeof(icp_common_t));
    /*
     * Only these fields need to be converted
     */
    header.length = ntohs(header.length);
    header.reqnum = ntohl(header.reqnum);
    header.flags = ntohl(header.flags);
    header.pad = ntohl(header.pad);

    switch (header.opcode) {
    case ICP_QUERY:
	/* We have a valid packet */
	url = buf + sizeof(icp_common_t) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    reply = icpCreateMessage(ICP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, PROTO_NONE);
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
		clientdbUpdate(from.sin_addr, LOG_UDP_DENIED, Config.Port.icp);
	    } else {
		reply = icpCreateMessage(ICP_DENIED, 0, url, header.reqnum, 0);
		icpUdpSend(fd, &from, reply, LOG_UDP_DENIED, icp_request->protocol);
	    }
	    break;
	}
	if (header.flags & ICP_FLAG_SRC_RTT) {
	    int rtt = netdbHostRtt(icp_request->host);
	    int hops = netdbHostHops(icp_request->host);
	    src_rtt = ((hops & 0xFFFF) << 16) | (rtt & 0xFFFF);
	    if (rtt)
		flags |= ICP_FLAG_SRC_RTT;
	}
	/* The peer is allowed to use this cache */
	key = storeKeyPublic(url, METHOD_GET);
	entry = storeGet(key);
	debug(12, 5) ("icpHandleIcpV2: OPCODE %s\n", icp_opcode_str[header.opcode]);
	if (icpCheckUdpHit(entry, icp_request)) {
	    reply = icpCreateMessage(ICP_HIT, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_HIT, icp_request->protocol);
	    break;
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (store_rebuilding && opt_reload_hit_only) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else if (hit_only_mode_until > squid_curtime) {
	    reply = icpCreateMessage(ICP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else {
	    reply = icpCreateMessage(ICP_MISS, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS, icp_request->protocol);
	}
	break;

    case ICP_HIT:
	Counter.icp.hits_recv++;
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
	    key = storeKeyPrivate(url, METHOD_GET, header.reqnum);
	else
	    key = storeKeyPublic(url, METHOD_GET);
	debug(12, 3) ("icpHandleIcpV2: Looking for key '%s'\n",
	    storeKeyText(key));
	if ((entry = storeGet(key)) == NULL) {
	    debug(12, 3) ("icpHandleIcpV2: Ignoring %s for NULL Entry.\n",
		icp_opcode_str[header.opcode]);
	} else {
	    /* call neighborsUdpAck even if ping_status != PING_WAITING */
	    neighborsUdpAck(url, &header, &from, entry);
	}
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
	stringClean(&icp_request->urlpath);
	memFree(MEM_REQUEST_T, icp_request);
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
icpHandleUdp(int sock, void *datanotused)
{
    struct sockaddr_in from;
    int from_len;
    LOCAL_ARRAY(char, buf, SQUID_UDP_SO_RCVBUF);
    int len;
    int icp_version;

    commSetSelect(sock, COMM_SELECT_READ, icpHandleUdp, NULL, 0);
    from_len = sizeof(from);
    memset(&from, '\0', from_len);
    len = recvfrom(sock,
	buf,
	SQUID_UDP_SO_RCVBUF - 1,
	0,
	(struct sockaddr *) &from,
	&from_len);
    if (len < 0) {
#ifdef _SQUID_LINUX_
	/* Some Linux systems seem to set the FD for reading and then
	 * return ECONNREFUSED when sendto() fails and generates an ICMP
	 * port unreachable message. */
	/* or maybe an EHOSTUNREACH "No route to host" message */
	if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif
	    debug(50, 1) ("icpHandleUdp: FD %d recvfrom: %s\n",
		sock, xstrerror());
	return;
    }
    Counter.icp.pkts_recv++;
    kb_incr(&Counter.icp.kbytes_recv, (size_t) len);
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
	return;
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
	"ICP Port");
    leave_suid();
    if (theInIcpConnection < 0)
	fatal("Cannot open ICP Port");
    fd_note(theInIcpConnection, "ICP socket");
    commSetSelect(theInIcpConnection,
	COMM_SELECT_READ,
	icpHandleUdp,
	NULL, 0);
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
	    NULL, 0);
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
