#include "squid.h"

static void icpLogIcp(icpUdpData *);
static void icpHandleIcpV2(int, struct sockaddr_in, char *, int);

static void
icpLogIcp(icpUdpData * queue)
{
    icp_common_t *header = (icp_common_t *) (void *) queue->msg;
    char *url = (char *) header + sizeof(icp_common_t);
    AccessLogEntry al;
    ICPCacheInfo->proto_touchobject(ICPCacheInfo,
	queue->proto,
	queue->len);
    ICPCacheInfo->proto_count(ICPCacheInfo,
	queue->proto,
	queue->logcode);
    clientdbUpdate(queue->address.sin_addr, queue->logcode, PROTO_ICP);
    if (!Config.onoff.log_udp)
	return;
    memset(&al, '\0', sizeof(AccessLogEntry));
    al.icp.opcode = ICP_OP_QUERY;
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
    while ((queue = UdpQueueHead)) {
	debug(12, 5) ("icpUdpReply: FD %d sending %d bytes to %s port %d\n",
	    fd,
	    queue->len,
	    inet_ntoa(queue->address.sin_addr),
	    ntohs(queue->address.sin_port));
	x = comm_udp_sendto(fd,
	    &queue->address,
	    sizeof(struct sockaddr_in),
	    queue->msg,
	    queue->len);
	if (x < 0) {
	    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
		break;		/* don't de-queue */
	}
	UdpQueueHead = queue->next;
	if (queue->logcode)
	    icpLogIcp(queue);
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
    assert(reqnum);
    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    headerp->flags = htonl(flags);
    headerp->pad = htonl(pad);
    headerp->shostid = htonl(theOutICPAddr.s_addr);
    urloffset = buf + sizeof(icp_common_t);
    if (opcode == ICP_OP_QUERY)
	urloffset += sizeof(u_num32);
    xmemcpy(urloffset, url, strlen(url));
    return buf;
}

#if USE_ICP_HIT_OBJ
static void *
icpCreateHitObjMessage(
    icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad,
    StoreEntry * entry)
{
    char *buf = NULL;
    char *entryoffset = NULL;
    char *urloffset = NULL;
    icp_common_t *headerp = NULL;
    int buf_len;
    u_short data_sz;
    int size;
    MemObject *m = entry->mem_obj;
    assert(m != NULL);
    buf_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;
    if (opcode == ICP_OP_QUERY)
	buf_len += sizeof(u_num32);
    buf = xcalloc(buf_len, 1);
    headerp = (icp_common_t *) (void *) buf;
    headerp->opcode = opcode;
    headerp->version = ICP_VERSION_CURRENT;
    headerp->length = htons(buf_len);
    headerp->reqnum = htonl(reqnum);
    headerp->flags = htonl(flags);
    headerp->pad = htonl(pad);
    headerp->shostid = htonl(theOutICPAddr.s_addr);
    urloffset = buf + sizeof(icp_common_t);
    xmemcpy(urloffset, url, strlen(url));
    data_sz = htons((u_short) entry->object_len);
    entryoffset = urloffset + strlen(url) + 1;
    xmemcpy(entryoffset, &data_sz, sizeof(u_short));
    entryoffset += sizeof(u_short);
    assert(m->data != NULL);
    size = memCopy(m->data, 0, entryoffset, entry->object_len);
    if (size < 0 || size != entry->object_len) {
	debug(12, 1) ("icpCreateHitObjMessage: copy failed, wanted %d got %d bytes\n",
	    entry->object_len, size);
	safe_free(buf);
	return NULL;
    }
    return buf;
}
#endif

void
icpUdpSend(int fd,
    const struct sockaddr_in *to,
    icp_common_t * msg,
    log_type logcode,
    protocol_t proto)
{
    icpUdpData *data = xcalloc(1, sizeof(icpUdpData));
    debug(12, 4) ("icpUdpSend: Queueing %s for %s\n",
	IcpOpcodeStr[msg->opcode],
	inet_ntoa(to->sin_addr));
    data->address = *to;
    data->msg = msg;
    data->len = (int) ntohs(msg->length);
#ifndef LESS_TIMING
    data->start = current_time;	/* wrong for HIT_OBJ */
#endif
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
    /* MUST NOT do UDP_HIT_OBJ if object is not in memory with async_io. The */
    /* icpHandleV2 code has not been written to support it - squid will die! */
#if USE_ASYNC_IO || defined(MEM_UDP_HIT_OBJ)
    if (e->mem_status != IN_MEMORY)
	return 0;
#endif
    return 1;
}

#if USE_ICP_HIT_OBJ
int
icpCheckUdpHitObj(StoreEntry * e, request_t * r, icp_common_t * h, int len)
{
    if (!BIT_TEST(h->flags, ICP_FLAG_HIT_OBJ))	/* not requested */
	return 0;
    if (len > Config.udpMaxHitObjsz)	/* too big */
	return 0;
    if (refreshCheck(e, r, 0))	/* stale */
	return 0;
#ifdef MEM_UDP_HIT_OBJ
    if (e->mem_status != IN_MEMORY)
	return 0;
#endif
    return 1;
}
#endif

static void
icpHandleIcpV2(int fd, struct sockaddr_in from, char *buf, int len)
{
    icp_common_t header;
    icp_common_t *headerp = (icp_common_t *) (void *) buf;
    StoreEntry *entry = NULL;
    char *url = NULL;
    const cache_key *key;
    request_t *icp_request = NULL;
    int allow = 0;
    char *data = NULL;
    u_short data_sz = 0;
    u_short u;
    int pkt_len;
    aclCheck_t checklist;
    icp_common_t *reply;
    int src_rtt = 0;
    u_num32 flags = 0;
    header.opcode = headerp->opcode;
    header.version = headerp->version;
    header.length = ntohs(headerp->length);
    header.reqnum = ntohl(headerp->reqnum);
    header.flags = ntohl(headerp->flags);
    header.shostid = ntohl(headerp->shostid);
    header.pad = ntohl(headerp->pad);

    switch (header.opcode) {
    case ICP_OP_QUERY:
	nudpconn++;
	/* We have a valid packet */
	url = buf + sizeof(header) + sizeof(u_num32);
	if ((icp_request = urlParse(METHOD_GET, url)) == NULL) {
	    reply = icpCreateMessage(ICP_OP_ERR, 0, url, header.reqnum, 0);
	    icpUdpSend(fd, &from, reply, LOG_UDP_INVALID, PROTO_NONE);
	    break;
	}
	checklist.src_addr = from.sin_addr;
	checklist.request = icp_request;
	allow = aclCheckFast(Config.accessList.icp, &checklist);
	if (!allow) {
	    debug(12, 2) ("icpHandleIcpV2: Access Denied for %s by %s.\n",
		inet_ntoa(from.sin_addr), AclMatchedName);
	    if (clientdbDeniedPercent(from.sin_addr) < 95) {
		reply = icpCreateMessage(ICP_OP_DENIED, 0, url, header.reqnum, 0);
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
	debug(12, 5) ("icpHandleIcpV2: OPCODE %s\n", IcpOpcodeStr[header.opcode]);
	if (icpCheckUdpHit(entry, icp_request)) {
	    pkt_len = sizeof(icp_common_t) + strlen(url) + 1 + 2 + entry->object_len;
#if USE_ICP_HIT_OBJ
	    if (icpCheckUdpHitObj(entry, icp_request, &header, pkt_len)) {
		reply = icpCreateHitObjMessage(ICP_OP_HIT_OBJ,
		    flags,
		    url,
		    header.reqnum,
		    src_rtt,
		    entry);
		icpUdpSend(fd, &from, reply, LOG_UDP_HIT, icp_request->protocol);
		break;
	    } else {
#endif
		reply = icpCreateMessage(ICP_OP_HIT, flags, url, header.reqnum, src_rtt);
		icpUdpSend(fd, &from, reply, LOG_UDP_HIT, icp_request->protocol);
		break;
#if USE_ICP_HIT_OBJ
	    }
#endif
	}
	/* if store is rebuilding, return a UDP_HIT, but not a MISS */
	if (store_rebuilding && opt_reload_hit_only) {
	    reply = icpCreateMessage(ICP_OP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else if (hit_only_mode_until > squid_curtime) {
	    reply = icpCreateMessage(ICP_OP_MISS_NOFETCH, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS_NOFETCH, icp_request->protocol);
	} else {
	    reply = icpCreateMessage(ICP_OP_MISS, flags, url, header.reqnum, src_rtt);
	    icpUdpSend(fd, &from, reply, LOG_UDP_MISS, icp_request->protocol);
	}
	break;

    case ICP_OP_HIT_OBJ:
    case ICP_OP_HIT:
    case ICP_OP_SECHO:
    case ICP_OP_DECHO:
    case ICP_OP_MISS:
    case ICP_OP_DENIED:
    case ICP_OP_MISS_NOFETCH:
	if (neighbors_do_private_keys && header.reqnum == 0) {
	    debug(12, 0) ("icpHandleIcpV2: Neighbor %s returned reqnum = 0\n",
		inet_ntoa(from.sin_addr));
	    debug(12, 0) ("icpHandleIcpV2: Disabling use of private keys\n");
	    neighbors_do_private_keys = 0;
	}
	url = buf + sizeof(header);
	if (header.opcode == ICP_OP_HIT_OBJ) {
	    data = url + strlen(url) + 1;
	    xmemcpy((char *) &u, data, sizeof(u_short));
	    data += sizeof(u_short);
	    data_sz = ntohs(u);
	    if ((int) data_sz > (len - (data - buf))) {
		debug(12, 0) ("icpHandleIcpV2: ICP_OP_HIT_OBJ object too small\n");
		break;
	    }
	}
	debug(12, 3) ("icpHandleIcpV2: %s from %s for '%s'\n",
	    IcpOpcodeStr[header.opcode],
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
		IcpOpcodeStr[header.opcode]);
	} else {
	    /* call neighborsUdpAck even if ping_status != PING_WAITING */
	    neighborsUdpAck(fd,
		url,
		&header,
		&from,
		entry,
		data,
		(int) data_sz);
	}
	break;

    case ICP_OP_INVALID:
    case ICP_OP_ERR:
	break;

    default:
	debug(12, 0) ("icpHandleIcpV2: UNKNOWN OPCODE: %d from %s\n",
	    header.opcode, inet_ntoa(from.sin_addr));
	break;
    }
    if (icp_request)
	put_free_request_t(icp_request);
}

#ifdef ICP_PKT_DUMP
static void
icpPktDump(icp_common_t * pkt)
{
    struct in_addr a;

    debug(12, 9) ("opcode:     %3d %s\n",
	(int) pkt->opcode,
	IcpOpcodeStr[pkt->opcode]);
    debug(12, 9) ("version: %-8d\n", (int) pkt->version);
    debug(12, 9) ("length:  %-8d\n", (int) ntohs(pkt->length));
    debug(12, 9) ("reqnum:  %-8d\n", ntohl(pkt->reqnum));
    debug(12, 9) ("flags:   %-8x\n", ntohl(pkt->flags));
    a.s_addr = ntohl(pkt->shostid);
    debug(12, 9) ("shostid: %s\n", inet_ntoa(a));
    debug(12, 9) ("payload: %s\n", (char *) pkt + sizeof(icp_common_t));
}
#endif

void
icpHandleUdp(int sock, void *not_used)
{
    struct sockaddr_in from;
    int from_len;
    LOCAL_ARRAY(char, buf, SQUID_UDP_SO_RCVBUF);
    int len;
    icp_common_t *headerp = NULL;
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
    headerp = (icp_common_t *) (void *) buf;
    if ((icp_version = (int) headerp->version) == ICP_VERSION_2)
	icpHandleIcpV2(sock, from, buf, len);
    else if (icp_version == ICP_VERSION_3)
	icpHandleIcpV3(sock, from, buf, len);
    else
	debug(12, 0) ("WARNING: Unused ICP version %d received from %s:%d\n",
	    icp_version,
	    inet_ntoa(from.sin_addr),
	    ntohs(from.sin_port));
}
