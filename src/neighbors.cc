/*
 * $Id: neighbors.cc,v 1.134 1997/04/30 16:18:43 wessels Exp $
 *
 * DEBUG: section 15    Neighbor Routines
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

/* count mcast group peers every 15 minutes */
#define MCAST_COUNT_RATE 900

static int peerAllowedToUse _PARAMS((const peer *, request_t *));
static int peerHTTPOkay _PARAMS((const peer *, request_t *));
static int peerWouldBePinged _PARAMS((const peer *, request_t *));
static void neighborRemove _PARAMS((peer *));
static peer *whichPeer _PARAMS((const struct sockaddr_in * from));
static void neighborAlive _PARAMS((peer *, const MemObject *, const icp_common_t *));
static void neighborCountIgnored _PARAMS((peer * e, icp_opcode op_unused));
static peer_t parseNeighborType _PARAMS((const char *s));
static void peerRefreshDNS _PARAMS((void *));
static void peerDNSConfigure _PARAMS((int fd, const ipcache_addrs * ia, void *data));
static void peerCheckConnect _PARAMS((void *));
static void peerCheckConnect2 _PARAMS((int, const ipcache_addrs *, void *));
static void peerCheckConnectDone _PARAMS((int, int, void *));
static void peerCountMcastPeersDone _PARAMS((void *data));
static void peerCountMcastPeersStart _PARAMS((void *data));
static void peerCountMcastPeersSchedule _PARAMS((peer * p, time_t when));
static void peerCountHandleIcpReply _PARAMS((peer * p, peer_t type, icp_opcode op, void *data));

static icp_common_t echo_hdr;
static u_short echo_port;

static int NLateReplies = 0;

static struct {
    int n;
    peer *peers_head;
    peer *peers_tail;
    peer *first_ping;
    peer *removed;
} Peers = {

    0, NULL, NULL, NULL
};

char *
neighborTypeStr(const peer * e)
{
    if (e->type == PEER_SIBLING)
	return "Sibling";
    if (e->type == PEER_MULTICAST)
	return "Multicast Group";
    return "Parent";
}


static peer *
whichPeer(const struct sockaddr_in *from)
{
    int j;
    u_short port = ntohs(from->sin_port);
    struct in_addr ip = from->sin_addr;
    peer *e = NULL;
    debug(15, 3, "whichPeer: from %s port %d\n", inet_ntoa(ip), port);
    for (e = Peers.peers_head; e; e = e->next) {
	for (j = 0; j < e->n_addresses; j++) {
	    if (ip.s_addr == e->addresses[j].s_addr && port == e->icp_port) {
		return e;
	    }
	}
    }
    return NULL;
}

void
hierarchyNote(request_t * request,
    hier_code code,
    icp_ping_data * icpdata,
    const char *cache_host)
{
    if (request == NULL)
	return;
    request->hierarchy.code = code;
    if (icpdata)
        request->hierarchy.icp = *icpdata;
    request->hierarchy.host = xstrdup(cache_host);
    request->hierarchy.icp.stop = current_time;
}

static peer_t
neighborType(const peer * e, const request_t * request)
{
    const struct _domain_type *d = NULL;
    for (d = e->typelist; d; d = d->next) {
	if (matchDomainName(d->domain, request->host))
	    if (d->type != PEER_NONE)
		return d->type;
    }
    return e->type;
}

/*
 * peerAllowedToUse
 *
 * this function figures out if it is appropriate to fetch REQUEST
 * from PEER.
 */
static int
peerAllowedToUse(const peer * e, request_t * request)
{
    const struct _domain_ping *d = NULL;
    int do_ping = 1;
    const struct _acl_list *a = NULL;
    aclCheck_t checklist;
    if (request == NULL)
	fatal_dump("peerAllowedToUse: NULL request");
    if (BIT_TEST(request->flags, REQ_NOCACHE))
	if (neighborType(e, request) == PEER_SIBLING)
	    return 0;
    if (BIT_TEST(request->flags, REQ_REFRESH))
	if (neighborType(e, request) == PEER_SIBLING)
	    return 0;
    if (e->pinglist == NULL && e->acls == NULL)
	return do_ping;
    do_ping = 0;
    for (d = e->pinglist; d; d = d->next) {
	if (matchDomainName(d->domain, request->host))
	    return d->do_ping;
	do_ping = !d->do_ping;
    }
    checklist.src_addr = request->client_addr;
    checklist.request = request;
    for (a = e->acls; a; a = a->next) {
	if (aclMatchAcl(a->acl, &checklist))
	    return a->op;
	do_ping = !a->op;
    }
    return do_ping;
}

/* Return TRUE if it is okay to send an ICP request to this peer.   */
static int
peerWouldBePinged(const peer * e, request_t * request)
{
    if (!peerAllowedToUse(e, request))
	return 0;
    if (e->options & NEIGHBOR_NO_QUERY)
	return 0;
    if (e->options & NEIGHBOR_MCAST_RESPONDER)
	return 0;
    /* the case below seems strange, but can happen if the
     * URL host is on the other side of a firewall */
    if (e->type == PEER_SIBLING)
	if (!BIT_TEST(request->flags, REQ_HIERARCHICAL))
	    return 0;
    if (e->icp_port == echo_port)
	if (!neighborUp(e))
	    return 0;
    if (e->n_addresses == 0)
	return 0;
    return 1;
}

/* Return TRUE if it is okay to send an HTTP request to this peer. */
static int
peerHTTPOkay(const peer * e, request_t * request)
{
    if (!peerAllowedToUse(e, request))
	return 0;
    if (!neighborUp(e))
	return 0;
    return 1;
}

int
neighborsCount(request_t * request)
{
    peer *e = NULL;
    int count = 0;
    for (e = Peers.peers_head; e; e = e->next)
	if (peerWouldBePinged(e, request))
	    count++;
    debug(15, 3, "neighborsCount: %d\n", count);
    return count;
}

peer *
getSingleParent(request_t * request)
{
    peer *p = NULL;
    peer *e = NULL;
    for (e = Peers.peers_head; e; e = e->next) {
	if (!peerHTTPOkay(e, request))
	    continue;
	if (neighborType(e, request) != PEER_PARENT)
	    return NULL;	/* oops, found SIBLING */
	if (p)
	    return NULL;	/* oops, found second parent */
	p = e;
    }
    debug(15, 3, "getSingleParent: returning %s\n", p ? p->host : "NULL");
    return p;
}

peer *
getFirstUpParent(request_t * request)
{
    peer *e = NULL;
    for (e = Peers.peers_head; e; e = e->next) {
	if (!neighborUp(e))
	    continue;
	if (neighborType(e, request) != PEER_PARENT)
	    continue;
	if (!peerHTTPOkay(e, request))
	    continue;
	break;
    }
    debug(15, 3, "getFirstUpParent: returning %s\n", e ? e->host : "NULL");
    return e;
}

peer *
getRoundRobinParent(request_t * request)
{
    peer *e;
    peer *f = NULL;
    for (e = Peers.peers_head; e; e = e->next) {
	if (!BIT_TEST(e->options, NEIGHBOR_ROUNDROBIN))
	    continue;
	if (neighborType(e, request) != PEER_PARENT)
	    continue;
	if (!peerHTTPOkay(e, request))
	    continue;
	if (f && f->rr_count < e->rr_count)
	    continue;
	f = e;
    }
    if (f)
	f->rr_count++;
    debug(15, 3, "getRoundRobinParent: returning %s\n", e ? e->host : "NULL");
    return f;
}

peer *
getDefaultParent(request_t * request)
{
    peer *e = NULL;
    for (e = Peers.peers_head; e; e = e->next) {
	if (neighborType(e, request) != PEER_PARENT)
	    continue;
	if (!BIT_TEST(e->options, NEIGHBOR_DEFAULT_PARENT))
	    continue;
	if (!peerHTTPOkay(e, request))
	    continue;
	debug(15, 3, "getDefaultParent: returning %s\n", e->host);
	return e;
    }
    return NULL;
}

peer *
getNextPeer(peer * e)
{
    return e->next;
}

peer *
getFirstPeer(void)
{
    return Peers.peers_head;
}

static void
neighborRemove(peer * target)
{
    peer *e = NULL;
    peer **E = NULL;
    e = Peers.peers_head;
    E = &Peers.peers_head;
    while (e) {
	if (target == e)
	    break;
	E = &e->next;
	e = e->next;
    }
    if (e) {
	*E = e->next;
	e->next = Peers.removed;
	Peers.removed = e;
	e->stats.ack_deficit = HIER_MAX_DEFICIT;
	Peers.n--;
    }
    Peers.first_ping = Peers.peers_head;
}

void
neighborsDestroy(void)
{
    peer *e = NULL;
    peer *next = NULL;

    debug(15, 3, "neighborsDestroy: called\n");

    for (e = Peers.peers_head; e; e = next) {
	next = e->next;
	peerDestroy(e);
	Peers.n--;
    }
    for (e = Peers.removed; e; e = next) {
	next = e->next;
	peerDestroy(e);
    }
    memset(&Peers, '\0', sizeof(Peers));
}

void
neighbors_open(int fd)
{
    struct sockaddr_in name;
    int len = sizeof(struct sockaddr_in);
    struct servent *sep = NULL;
    memset(&name, '\0', sizeof(struct sockaddr_in));
    if (getsockname(fd, (struct sockaddr *) &name, &len) < 0)
	debug(15, 1, "getsockname(%d,%p,%p) failed.\n", fd, &name, &len);
    peerRefreshDNS(NULL);
    if (0 == echo_hdr.opcode) {
	echo_hdr.opcode = ICP_OP_SECHO;
	echo_hdr.version = ICP_VERSION_CURRENT;
	echo_hdr.length = 0;
	echo_hdr.reqnum = 0;
	echo_hdr.flags = 0;
	echo_hdr.pad = 0;
	/* memset(echo_hdr.auth, '\0', sizeof(u_num32) * ICP_AUTH_SIZE); */
	echo_hdr.shostid = name.sin_addr.s_addr;
	sep = getservbyname("echo", "udp");
	echo_port = sep ? ntohs((u_short) sep->s_port) : 7;
    }
}

int
neighborsUdpPing(request_t * request,
    StoreEntry * entry,
    IRCB * callback,
    void *callback_data,
    int *exprep)
{
    char *host = request->host;
    char *url = entry->url;
    MemObject *mem = entry->mem_obj;
    const ipcache_addrs *ia = NULL;
    struct sockaddr_in to_addr;
    peer *e = NULL;
    int i;
    int reqnum = 0;
    int flags;
    icp_common_t *query;
    int queries_sent = 0;
    int peers_pinged = 0;

    if (Peers.peers_head == NULL)
	return 0;
    if (theOutIcpConnection < 0) {
	debug(15, 0, "neighborsUdpPing: There is no ICP socket!\n");
	debug(15, 0, "Cannot query neighbors for '%s'.\n", url);
	debug(15, 0, "Check 'icp_port' in your config file\n");
	fatal_dump(NULL);
    }
    if (entry->swap_status != NO_SWAP)
	fatal_dump("neighborsUdpPing: bad swap_status");
    mem->w_rtt = 0;
    mem->e_pings_closest_parent = NULL;
    mem->p_rtt = 0;
    mem->start_ping = current_time;
    mem->icp_reply_callback = callback;
    mem->ircb_data = callback_data;
    for (i = 0, e = Peers.first_ping; i++ < Peers.n; e = e->next) {
	if (e == NULL)
	    e = Peers.peers_head;
	debug(15, 5, "neighborsUdpPing: Peer %s\n", e->host);
	if (!peerWouldBePinged(e, request))
	    continue;		/* next peer */
	peers_pinged++;
	debug(15, 4, "neighborsUdpPing: pinging peer %s for '%s'\n",
	    e->host, url);
	if (e->type == PEER_MULTICAST)
	    comm_set_mcast_ttl(theOutIcpConnection, e->mcast.ttl);
	reqnum = storeReqnum(entry, request->method);
	debug(15, 3, "neighborsUdpPing: key = '%s'\n", entry->key);
	debug(15, 3, "neighborsUdpPing: reqnum = %d\n", reqnum);

	if (e->icp_port == echo_port) {
	    debug(15, 4, "neighborsUdpPing: Looks like a dumb cache, send DECHO ping\n");
	    echo_hdr.reqnum = reqnum;
	    query = icpCreateMessage(ICP_OP_DECHO, 0, url, reqnum, 0);
	    icpUdpSend(theOutIcpConnection,
		&e->in_addr,
		query,
		LOG_TAG_NONE,
		PROTO_NONE);
	} else {
	    flags = 0;
	    /* check if we should set ICP_FLAG_HIT_OBJ */
	    if (opt_udp_hit_obj)
		if (!BIT_TEST(request->flags, REQ_NOCACHE))
		    if (e->icp_version == ICP_VERSION_2)
			flags |= ICP_FLAG_HIT_OBJ;
	    if (Config.Options.query_icmp)
		if (e->icp_version == ICP_VERSION_2)
		    flags |= ICP_FLAG_SRC_RTT;
	    query = icpCreateMessage(ICP_OP_QUERY, flags, url, reqnum, 0);
	    icpUdpSend(theOutIcpConnection,
		&e->in_addr,
		query,
		LOG_TAG_NONE,
		PROTO_NONE);
	}
	queries_sent++;

	e->stats.ack_deficit++;
	e->stats.pings_sent++;
	debug(15, 3, "neighborsUdpPing: %s: ack_deficit = %d\n",
	    e->host, e->stats.ack_deficit);
	if (e->type == PEER_MULTICAST) {
	    e->stats.ack_deficit = 0;
	    (*exprep) += e->mcast.n_replies_expected;
	} else if (neighborUp(e)) {
	    /* its alive, expect a reply from it */
	    (*exprep)++;
	} else {
	    /* Neighbor is dead; ping it anyway, but don't expect a reply */
	    /* log it once at the threshold */
	    if ((e->stats.ack_deficit == HIER_MAX_DEFICIT)) {
		debug(15, 0, "Detected DEAD %s: %s/%d/%d\n",
		    neighborTypeStr(e),
		    e->host, e->http_port, e->icp_port);
	    }
	}
    }
    if ((Peers.first_ping = Peers.first_ping->next) == NULL)
	Peers.first_ping = Peers.peers_head;

    /* only do source_ping if we have neighbors */
    if (Peers.n) {
	if (Config.sourcePing) {
	    debug(15, 6, "neighborsUdpPing: Source Ping is disabled.\n");
	} else if ((ia = ipcache_gethostbyname(host, 0))) {
	    debug(15, 6, "neighborsUdpPing: Source Ping: to %s for '%s'\n",
		host, url);
	    echo_hdr.reqnum = reqnum;
	    if (icmp_sock != -1) {
		icmpSourcePing(ia->in_addrs[ia->cur], &echo_hdr, url);
	    } else {
		to_addr.sin_family = AF_INET;
		to_addr.sin_addr = ia->in_addrs[ia->cur];
		to_addr.sin_port = htons(echo_port);
		query = icpCreateMessage(ICP_OP_SECHO, 0, url, reqnum, 0);
		icpUdpSend(theOutIcpConnection,
		    &to_addr,
		    query,
		    LOG_TAG_NONE,
		    PROTO_NONE);
	    }
	} else {
	    debug(15, 6, "neighborsUdpPing: Source Ping: unknown host: %s\n",
		host);
	}
    }
#if LOG_ICP_NUMBERS
    request->hierarchy.n_sent = peers_pinged;
    request->hierarchy.n_expect = *exprep;
#endif
    return peers_pinged;
}

static void
neighborAlive(peer * e, const MemObject * mem, const icp_common_t * header)
{
    int rtt;
    int n;
    /* Neighbor is alive, reset the ack deficit */
    if (e->stats.ack_deficit >= HIER_MAX_DEFICIT) {
	debug(15, 0, "Detected REVIVED %s: %s/%d/%d\n",
	    neighborTypeStr(e),
	    e->host, e->http_port, e->icp_port);
    }
    e->stats.ack_deficit = 0;
    n = ++e->stats.pings_acked;
    if ((icp_opcode) header->opcode <= ICP_OP_END)
	e->stats.counts[header->opcode]++;
    if (n > RTT_AV_FACTOR)
	n = RTT_AV_FACTOR;
    if (mem) {
	rtt = tvSubMsec(mem->start_ping, current_time);
	e->stats.rtt = (e->stats.rtt * (n - 1) + rtt) / n;
	e->icp_version = (int) header->version;
    }
}

static void
neighborCountIgnored(peer * e, icp_opcode op_unused)
{
    if (e == NULL)
	return;
    e->stats.ignored_replies++;
    NLateReplies++;
}

/* ignoreMulticastReply
 * 
 * We want to ignore replies from multicast peers if the
 * cache_host_domain rules would normally prevent the peer
 * from being used
 */
static int
ignoreMulticastReply(peer * e, MemObject * mem)
{
    if (e == NULL)
	return 0;
    if (!BIT_TEST(e->options, NEIGHBOR_MCAST_RESPONDER))
	return 0;
    if (peerHTTPOkay(e, mem->request))
	return 0;
    return 1;
}

/* I should attach these records to the entry.  We take the first
 * hit we get our wait until everyone misses.  The timeout handler
 * call needs to nip this shopping list or call one of the misses.
 * 
 * If a hit process is already started, then sobeit
 */
void
neighborsUdpAck(int fd, const char *url, icp_common_t * header, const struct sockaddr_in *from, StoreEntry * entry, char *data, int data_sz)
{
    peer *e = NULL;
    MemObject *mem = entry->mem_obj;
    peer_t ntype = PEER_NONE;
    char *opcode_d;
    icp_opcode opcode = (icp_opcode) header->opcode;

    debug(15, 6, "neighborsUdpAck: opcode %d '%s'\n", (int) opcode, url);
    if ((e = whichPeer(from)))
	neighborAlive(e, mem, header);
    if (opcode > ICP_OP_END)
	return;
    opcode_d = IcpOpcodeStr[opcode];
    /* check if someone is already fetching it */
    if (BIT_TEST(entry->flag, ENTRY_DISPATCHED)) {
	debug(15, 3, "neighborsUdpAck: '%s' already being fetched.\n", url);
	neighborCountIgnored(e, opcode);
	return;
    }
    if (mem == NULL) {
	debug(15, 2, "Ignoring %s for missing mem_obj: %s\n", opcode_d, url);
	neighborCountIgnored(e, opcode);
	return;
    }
    if (entry->ping_status != PING_WAITING) {
	debug(15, 2, "neighborsUdpAck: Unexpected %s for %s\n", opcode_d, url);
	neighborCountIgnored(e, opcode);
	return;
    }
    if (entry->lock_count == 0) {
	debug(12, 1, "neighborsUdpAck: '%s' has no locks\n", url);
	neighborCountIgnored(e, opcode);
	return;
    }
    debug(15, 3, "neighborsUdpAck: %s for '%s' from %s \n",
	opcode_d, url, e ? e->host : "source");
    if (e)
	ntype = neighborType(e, mem->request);
    if (ignoreMulticastReply(e, mem)) {
	neighborCountIgnored(e, opcode);
    } else if (opcode == ICP_OP_SECHO) {
	/* Received source-ping reply */
	if (e) {
	    debug(15, 1, "Ignoring SECHO from neighbor %s\n", e->host);
	    neighborCountIgnored(e, opcode);
	} else {
	    /* if we reach here, source-ping reply is the first 'parent',
	     * so fetch directly from the source */
	    debug(15, 6, "Source is the first to respond.\n");
	    hierarchyNote(entry->mem_obj->request,
		SOURCE_FASTEST,
		0,
		fqdnFromAddr(from->sin_addr));
	    entry->ping_status = PING_DONE;
	    protoStart(0, entry, NULL, entry->mem_obj->request);
	    return;
	}
    } else if (opcode == ICP_OP_MISS) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring MISS from non-peer %s\n",
		inet_ntoa(from->sin_addr));
	} else if (ntype != PEER_PARENT) {
	    (void) 0;		/* ignore MISS from non-parent */
	} else {
	    mem->icp_reply_callback(e, ntype, opcode, mem->ircb_data);
	}
    } else if (opcode == ICP_OP_HIT || opcode == ICP_OP_HIT_OBJ) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring HIT from non-peer %s\n",
		inet_ntoa(from->sin_addr));
	} else {
	    mem->icp_reply_callback(e, ntype, ICP_OP_HIT, mem->ircb_data);
	}
    } else if (opcode == ICP_OP_DECHO) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring DECHO from non-peer %s\n",
		inet_ntoa(from->sin_addr));
	} else if (ntype == PEER_SIBLING) {
	    debug_trap("neighborsUdpAck: Found non-ICP cache as SIBLING\n");
	    debug_trap("neighborsUdpAck: non-ICP neighbors must be a PARENT\n");
	} else {
	    mem->icp_reply_callback(e, ntype, opcode, mem->ircb_data);
	}
    } else if (opcode == ICP_OP_SECHO) {
	if (e) {
	    debug(15, 1, "Ignoring SECHO from neighbor %s\n", e->host);
	    neighborCountIgnored(e, opcode);
	} else if (!Config.sourcePing) {
	    debug(15, 1, "Unsolicited SECHO from %s\n", inet_ntoa(from->sin_addr));
	} else {
	    mem->icp_reply_callback(NULL, ntype, opcode, mem->ircb_data);
	}
    } else if (opcode == ICP_OP_DENIED) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring DENIED from non-peer %s\n",
		inet_ntoa(from->sin_addr));
	} else if (e->stats.pings_acked > 100) {
	    if (100 * e->stats.counts[ICP_OP_DENIED] / e->stats.pings_acked > 95) {
		debug(15, 0, "95%% of replies from '%s' are UDP_DENIED\n", e->host);
		debug(15, 0, "Disabling '%s', please check your configuration.\n", e->host);
		neighborRemove(e);
		e = NULL;
	    } else {
		neighborCountIgnored(e, opcode);
	    }
	}
    } else if (opcode == ICP_OP_MISS_NOFETCH) {
	mem->icp_reply_callback(e, ntype, opcode, mem->ircb_data);
    } else {
	debug(15, 0, "neighborsUdpAck: Unexpected ICP reply: %s\n", opcode_d);
    }
}

void
neighborAdd(const char *host,
    const char *type,
    int http_port,
    int icp_port,
    int options,
    int weight,
    int mcast_ttl)
{
    peer *e = NULL;
    const char *me = getMyHostname();
    if (!strcmp(host, me) && http_port == Config.Port.http) {
	debug(15, 0, "neighborAdd: skipping cache_host %s %s/%d/%d\n",
	    type, host, http_port, icp_port);
	return;
    }
    e = xcalloc(1, sizeof(peer));
    e->http_port = http_port;
    e->icp_port = icp_port;
    e->mcast.ttl = mcast_ttl;
    e->options = options;
    e->weight = weight;
    e->host = xstrdup(host);
    e->pinglist = NULL;
    e->typelist = NULL;
    e->acls = NULL;
    e->icp_version = ICP_VERSION_CURRENT;
    e->type = parseNeighborType(type);
    e->tcp_up = 1;

    /* Append peer */
    if (!Peers.peers_head)
	Peers.peers_head = e;
    if (Peers.peers_tail)
	Peers.peers_tail->next = e;
    Peers.peers_tail = e;
    Peers.n++;
    if (!Peers.first_ping)
	Peers.first_ping = e;
}

void
neighborAddDomainPing(const char *host, const char *domain)
{
    struct _domain_ping *l = NULL;
    struct _domain_ping **L = NULL;
    peer *e;
    if ((e = neighborFindByName(host)) == NULL) {
	debug(15, 0, "%s, line %d: No cache_host '%s'\n",
	    cfg_filename, config_lineno, host);
	return;
    }
    l = xmalloc(sizeof(struct _domain_ping));
    l->do_ping = 1;
    if (*domain == '!') {	/* check for !.edu */
	l->do_ping = 0;
	domain++;
    }
    l->domain = xstrdup(domain);
    l->next = NULL;
    for (L = &(e->pinglist); *L; L = &((*L)->next));
    *L = l;
}

void
neighborAddDomainType(const char *host, const char *domain, const char *type)
{
    struct _domain_type *l = NULL;
    struct _domain_type **L = NULL;
    peer *e;
    if ((e = neighborFindByName(host)) == NULL) {
	debug(15, 0, "%s, line %d: No cache_host '%s'\n",
	    cfg_filename, config_lineno, host);
	return;
    }
    l = xmalloc(sizeof(struct _domain_type));
    l->type = parseNeighborType(type);
    l->domain = xstrdup(domain);
    l->next = NULL;
    for (L = &(e->typelist); *L; L = &((*L)->next));
    *L = l;
}

void
neighborAddAcl(const char *host, const char *aclname)
{
    peer *e;
    struct _acl_list *L = NULL;
    struct _acl_list **Tail = NULL;
    struct _acl *a = NULL;

    if ((e = neighborFindByName(host)) == NULL) {
	debug(15, 0, "%s, line %d: No cache_host '%s'\n",
	    cfg_filename, config_lineno, host);
	return;
    }
    L = xcalloc(1, sizeof(struct _acl_list));
    L->op = 1;
    if (*aclname == '!') {
	L->op = 0;
	aclname++;
    }
    debug(15, 3, "neighborAddAcl: looking for ACL name '%s'\n", aclname);
    a = aclFindByName(aclname);
    if (a == NULL) {
	debug(15, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(15, 0, "neighborAddAcl: ACL name '%s' not found.\n", aclname);
	xfree(L);
	return;
    }
#ifdef NOW_SUPPORTED
    if (a->type == ACL_SRC_IP) {
	debug(15, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(15, 0, "neighborAddAcl: 'src' ACL's not supported for 'cache_host_acl'\n");
	xfree(L);
	return;
    }
#endif
    L->acl = a;
    for (Tail = &(e->acls); *Tail; Tail = &((*Tail)->next));
    *Tail = L;
}

peer *
neighborFindByName(const char *name)
{
    peer *e = NULL;
    for (e = Peers.peers_head; e; e = e->next) {
	if (!strcasecmp(name, e->host))
	    break;
    }
    return e;
}

static peer_t
parseNeighborType(const char *s)
{
    if (!strcasecmp(s, "parent"))
	return PEER_PARENT;
    if (!strcasecmp(s, "neighbor"))
	return PEER_SIBLING;
    if (!strcasecmp(s, "neighbour"))
	return PEER_SIBLING;
    if (!strcasecmp(s, "sibling"))
	return PEER_SIBLING;
    if (!strcasecmp(s, "multicast"))
	return PEER_MULTICAST;
    debug(15, 0, "WARNING: Unknown neighbor type: %s\n", s);
    return PEER_SIBLING;
}

int
neighborUp(const peer * e)
{
    if (!e->tcp_up)
	return 0;
    if (e->stats.ack_deficit >= HIER_MAX_DEFICIT)
	return 0;
    return 1;
}

void
peerDestroy(peer * e)
{
    struct _domain_ping *l = NULL;
    struct _domain_ping *nl = NULL;
    if (e == NULL)
	return;
    if (!e->tcp_up)
	eventDelete(peerCheckConnect, e);
    if (e->type == PEER_MULTICAST) {
	if (e->mcast.flags & PEER_COUNT_EVENT_PENDING)
	    eventDelete(peerCountMcastPeersStart, e);
	if (e->mcast.flags & PEER_COUNTING)
	    eventDelete(peerCountMcastPeersDone, e);
    }
    for (l = e->pinglist; l; l = nl) {
	nl = l->next;
	safe_free(l->domain);
	safe_free(l);
    }
    if (e->ip_lookup_pending)
	ipcache_unregister(e->host, e->ipcache_fd);
    safe_free(e->host);
    safe_free(e);
}

static void
peerDNSConfigure(int fd, const ipcache_addrs * ia, void *data)
{
    peer *e = data;
    struct sockaddr_in *ap;
    int j;
    e->ip_lookup_pending = 0;
    if (e->n_addresses == 0) {
	debug(15, 1, "Configuring %s %s/%d/%d\n", neighborTypeStr(e),
	    e->host, e->http_port, e->icp_port);
	if (e->type == PEER_MULTICAST)
	    debug(15, 1, "    Multicast TTL = %d\n", e->mcast.ttl);
    }
    e->n_addresses = 0;
    if (ia == NULL) {
	debug(0, 0, "WARNING: DNS lookup for '%s' failed!\n", e->host);
	return;
    }
    if ((int) ia->count < 1) {
	debug(0, 0, "WARNING: No IP address found for '%s'!\n", e->host);
	return;
    }
    for (j = 0; j < (int) ia->count && j < PEER_MAX_ADDRESSES; j++) {
	e->addresses[j] = ia->in_addrs[j];
	debug(15, 2, "--> IP address #%d: %s\n", j, inet_ntoa(e->addresses[j]));
	e->n_addresses++;
    }
    ap = &e->in_addr;
    memset(ap, '\0', sizeof(struct sockaddr_in));
    ap->sin_family = AF_INET;
    ap->sin_addr = e->addresses[0];
    ap->sin_port = htons(e->icp_port);
    if (e->type == PEER_MULTICAST)
	peerCountMcastPeersSchedule(e, 10);
}

static void
peerRefreshDNS(void *junk)
{
    peer *e = NULL;
    peer *next = Peers.peers_head;
    while ((e = next)) {
	next = e->next;
	e->ip_lookup_pending = 1;
	/* some random, bogus FD for ipcache */
	e->ipcache_fd = Squid_MaxFD + current_time.tv_usec;
	ipcache_nbgethostbyname(e->host, e->ipcache_fd, peerDNSConfigure, e);
    }
    /* Reconfigure the peers every hour */
    eventAdd("peerRefreshDNS", peerRefreshDNS, NULL, 3600);
}

static void
peerCheckConnect(void *data)
{
    peer *p = data;
    int fd;
    fd = comm_open(SOCK_STREAM, 0, Config.Addrs.tcp_outgoing,
	0, COMM_NONBLOCKING, p->host);
    if (fd < 0)
	return;
    p->ip_lookup_pending = 1;
    p->ipcache_fd = fd;
    ipcache_nbgethostbyname(p->host, fd, peerCheckConnect2, p);
}

static void
peerCheckConnect2(int fd, const ipcache_addrs * ia, void *data)
{
    peer *p = data;
    p->ip_lookup_pending = 0;
    commConnectStart(fd,
	p->host,
	p->http_port,
	peerCheckConnectDone,
	p);
}

static void
peerCheckConnectDone(int fd, int status, void *data)
{
    peer *p = data;
    p->tcp_up = status == COMM_OK ? 1 : 0;
    if (p->tcp_up) {
	debug(15, 0, "TCP connection to %s/%d succeeded\n",
	    p->host, p->http_port);
    } else {
	eventAdd("peerCheckConnect", peerCheckConnect, p, 80);
    }
    comm_close(fd);
    return;
}

void
peerCheckConnectStart(peer * p)
{
    if (!p->tcp_up)
	return;
    debug(15, 0, "TCP connection to %s/%d failed\n", p->host, p->http_port);
    p->tcp_up = 0;
    p->last_fail_time = squid_curtime;
    eventAdd("peerCheckConnect", peerCheckConnect, p, 80);
}

static void
peerCountMcastPeersSchedule(peer * p, time_t when)
{
    if (p->mcast.flags & PEER_COUNT_EVENT_PENDING)
	return;
    eventAdd("peerCountMcastPeersStart",
	peerCountMcastPeersStart,
	p,
	when);
    p->mcast.flags |= PEER_COUNT_EVENT_PENDING;
}

static void
peerCountMcastPeersStart(void *data)
{
    peer *p = data;
    ps_state *psstate = xcalloc(1, sizeof(ps_state));
    StoreEntry *fake;
    MemObject *mem;
    icp_common_t *query;
    LOCAL_ARRAY(char, url, MAX_URL);
    if (p->type != PEER_MULTICAST)
	fatal_dump("peerCountMcastPeersStart: non-multicast peer");
    p->mcast.flags &= ~PEER_COUNT_EVENT_PENDING;
    sprintf(url, "http://%s/", inet_ntoa(p->in_addr.sin_addr));
    fake = storeCreateEntry(url, NULL, 0, 0, METHOD_GET);
    psstate->request = requestLink(urlParse(METHOD_GET, url));
    psstate->entry = fake;
    psstate->callback = NULL;
    psstate->fail_callback = NULL;
    psstate->callback_data = p;
    psstate->icp.start = current_time;
    mem = fake->mem_obj;
    mem->request = requestLink(psstate->request);
    mem->start_ping = current_time;
    mem->icp_reply_callback = peerCountHandleIcpReply;
    mem->ircb_data = psstate;
    comm_set_mcast_ttl(theOutIcpConnection, p->mcast.ttl);
    p->mcast.reqnum = storeReqnum(fake, METHOD_GET);
    query = icpCreateMessage(ICP_OP_QUERY, 0, url, p->mcast.reqnum, 0);
    icpUdpSend(theOutIcpConnection,
	&p->in_addr,
	query,
	LOG_TAG_NONE,
	PROTO_NONE);
    fake->ping_status = PING_WAITING;
    eventAdd("peerCountMcastPeersDone",
	peerCountMcastPeersDone,
	psstate,
	Config.neighborTimeout);
    p->mcast.flags |= PEER_COUNTING;
    peerCountMcastPeersSchedule(p, MCAST_COUNT_RATE);
}

static void
peerCountMcastPeersDone(void *data)
{
    ps_state *psstate = data;
    peer *p = psstate->callback_data;
    StoreEntry *fake = psstate->entry;
    double old;
    double new;
    double D;
    p->mcast.flags &= ~PEER_COUNTING;
    D = (double) ++p->mcast.n_times_counted;
    if (D > 10.0)
	D = 10.0;
    old = p->mcast.avg_n_members;
    new = (double) psstate->icp.n_recv;
    p->mcast.avg_n_members = (old * (D - 1.0) + new) / D;
    debug(15, 1, "Group %s: %d replies, %4.1f average\n",
	p->host,
	psstate->icp.n_recv,
	p->mcast.avg_n_members);
    p->mcast.n_replies_expected = (int) p->mcast.avg_n_members;
    fake->store_status = STORE_ABORTED;
    storeReleaseRequest(fake);
    storeUnlockObject(fake);
    xfree(psstate);
}

static void
peerCountHandleIcpReply(peer * p, peer_t type, icp_opcode op, void *data)
{
    ps_state *psstate = data;
    psstate->icp.n_recv++;
    debug(0, 0, "peerCountHandleIcpReply: %d replies\n", psstate->icp.n_recv);
}
