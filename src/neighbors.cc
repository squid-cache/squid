/*
 * $Id: neighbors.cc,v 1.95 1996/12/05 23:12:21 wessels Exp $
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

static int edgeWouldBePinged _PARAMS((const edge *, request_t *));
static void neighborRemove _PARAMS((edge *));
static edge *whichEdge _PARAMS((const struct sockaddr_in * from));
static void neighborAlive _PARAMS((edge *, const MemObject *, const icp_common_t *));
static void neighborCountIgnored _PARAMS((edge * e, icp_opcode op_unused));
static neighbor_t parseNeighborType _PARAMS((const char *s));

static icp_common_t echo_hdr;
static u_short echo_port;

static struct {
    int n;
    edge *edges_head;
    edge *edges_tail;
    edge *first_ping;
} friends = {

    0, NULL, NULL, NULL
};

const char *hier_strings[] =
{
    "NONE",
    "DIRECT",
    "SIBLING_HIT",
    "PARENT_HIT",
    "DEFAULT_PARENT",
    "SINGLE_PARENT",
    "FIRST_UP_PARENT",
    "NO_PARENT_DIRECT",
    "FIRST_PARENT_MISS",
    "LOCAL_IP_DIRECT",
    "FIREWALL_IP_DIRECT",
    "NO_DIRECT_FAIL",
    "SOURCE_FASTEST",
    "SIBLING_UDP_HIT_OBJ",
    "PARENT_UDP_HIT_OBJ",
    "PASSTHROUGH_PARENT",
    "INVALID CODE"
};


static edge *
whichEdge(const struct sockaddr_in *from)
{
    int j;
    u_short port = ntohs(from->sin_port);
    struct in_addr ip = from->sin_addr;
    edge *e = NULL;
    debug(15, 3, "whichEdge: from %s port %d\n", inet_ntoa(ip), port);
    for (e = friends.edges_head; e; e = e->next) {
	for (j = 0; j < e->n_addresses; j++) {
	    if (ip.s_addr == e->addresses[j].s_addr && port == e->icp_port) {
		return e;
	    }
	}
    }
    return NULL;
}

void
hierarchyNote(request_t * request, hier_code code, int timeout, const char *cache_host)
{
    if (request) {
	request->hierarchy.code = code;
	request->hierarchy.timeout = timeout;
	request->hierarchy.host = xstrdup(cache_host);
    }
}

static neighbor_t
neighborType(const edge * e, const request_t * request)
{
    const struct _domain_type *d = NULL;
    for (d = e->typelist; d; d = d->next) {
	if (matchDomainName(d->domain, request->host))
	    if (d->type != EDGE_NONE)
		return d->type;
    }
    return e->type;
}

static int
edgeWouldBePinged(const edge * e, request_t * request)
{
    const struct _domain_ping *d = NULL;
    int do_ping = 1;
    const struct _acl_list *a = NULL;
    aclCheck_t checklist;

    if (BIT_TEST(request->flags, REQ_NOCACHE))
	if (neighborType(e, request) == EDGE_SIBLING)
	    return 0;
    if (BIT_TEST(request->flags, REQ_REFRESH))
	if (neighborType(e, request) == EDGE_SIBLING)
	    return 0;
    if (e->pinglist == NULL && e->acls == NULL)
	return do_ping;
    do_ping = 0;
    for (d = e->pinglist; d; d = d->next) {
	if (matchDomainName(d->domain, request->host))
	    return d->do_ping;
	do_ping = !d->do_ping;
    }
    checklist.src_addr = any_addr;	/* XXX bogus! */
    checklist.request = request;
    for (a = e->acls; a; a = a->next) {
	if (aclMatchAcl(a->acl, &checklist))
	    return a->op;
	do_ping = !a->op;
    }
    return do_ping;
}

int
neighborsCount(request_t * request)
{
    edge *e = NULL;
    int count = 0;
    for (e = friends.edges_head; e; e = e->next)
	if (edgeWouldBePinged(e, request))
	    count++;
    return count;
}

edge *
getSingleParent(request_t * request)
{
    edge *p = NULL;
    edge *e = NULL;
    for (e = friends.edges_head; e; e = e->next) {
	if (!edgeWouldBePinged(e, request))
	    continue;
	if (neighborType(e, request) != EDGE_PARENT)
	    return NULL;	/* oops, found SIBLING */
	if (p)
	    return NULL;	/* oops, found second parent */
	p = e;
    }
    return p;
}

edge *
getFirstUpParent(request_t * request)
{
    edge *e = NULL;
    for (e = friends.edges_head; e; e = e->next) {
	if (!neighborUp(e))
	    continue;
	if (neighborType(e, request) != EDGE_PARENT)
	    continue;
	if (edgeWouldBePinged(e, request))
	    return e;
    }
    return NULL;
}

edge *
getDefaultParent(request_t * request)
{
    edge *e = NULL;
    for (e = friends.edges_head; e; e = e->next) {
	if (!neighborUp(e))
	    continue;
	if (neighborType(e, request) != EDGE_PARENT)
	    continue;
	if (!BIT_SET(e->options, NEIGHBOR_DEFAULT_PARENT))
	    continue;
	if (!edgeWouldBePinged(e, request))
	    continue;
	return e;
    }
    return NULL;
}

edge *
getNextEdge(edge * e)
{
    return e->next;
}

edge *
getFirstEdge(void)
{
    return friends.edges_head;
}

static void
neighborRemove(edge * target)
{
    edge *e = NULL;
    edge **E = NULL;
    e = friends.edges_head;
    E = &friends.edges_head;
    while (e) {
	if (target == e)
	    break;
	E = &e->next;
	e = e->next;
    }
    if (e) {
	*E = e->next;
	safe_free(e->host);
	safe_free(e);
	friends.n--;
    }
}

void
neighborsDestroy(void)
{
    edge *e = NULL;
    edge *next = NULL;

    debug(15, 3, "neighborsDestroy: called\n");

    for (e = friends.edges_head; e; e = next) {
	next = e->next;
	edgeDestroy(e);
	friends.n--;
    }
    memset(&friends, '\0', sizeof(friends));
}

void
neighbors_open(int fd)
{
    int j;
    struct sockaddr_in name;
    struct sockaddr_in *ap;
    int len = sizeof(struct sockaddr_in);
    const ipcache_addrs *ia = NULL;
    edge *e = NULL;
    edge *next = NULL;
    edge **E = NULL;
    struct servent *sep = NULL;

    memset(&name, '\0', sizeof(struct sockaddr_in));
    if (getsockname(fd, (struct sockaddr *) &name, &len) < 0)
	debug(15, 1, "getsockname(%d,%p,%p) failed.\n", fd, &name, &len);

    /* Prepare neighbor connections, one at a time */
    E = &friends.edges_head;
    next = friends.edges_head;
    while ((e = next)) {
	getCurrentTime();
	next = e->next;
	debug(15, 1, "Configuring neighbor %s/%d/%d\n",
	    e->host, e->http_port, e->icp_port);
	if ((ia = ipcache_gethostbyname(e->host, IP_BLOCKING_LOOKUP)) == NULL) {
	    debug(0, 0, "WARNING!!: DNS lookup for '%s' failed!\n", e->host);
	    debug(0, 0, "THIS NEIGHBOR WILL BE IGNORED.\n");
	    *E = next;		/* skip */
	    safe_free(e);
	    continue;
	}
	e->n_addresses = 0;
	for (j = 0; j < (int) ia->count && j < EDGE_MAX_ADDRESSES; j++) {
	    e->addresses[j] = ia->in_addrs[j];
	    e->n_addresses++;
	}
	if (e->n_addresses < 1) {
	    debug(0, 0, "WARNING!!: No IP address found for '%s'!\n", e->host);
	    debug(0, 0, "THIS NEIGHBOR WILL BE IGNORED.\n");
	    *E = next;		/* skip */
	    safe_free(e);
	    continue;
	}
	for (j = 0; j < e->n_addresses; j++) {
	    debug(15, 2, "--> IP address #%d: %s\n",
		j, inet_ntoa(e->addresses[j]));
	}
	e->stats.rtt = 0;

	ap = &e->in_addr;
	memset(ap, '\0', sizeof(struct sockaddr_in));
	ap->sin_family = AF_INET;
	ap->sin_addr = e->addresses[0];
	ap->sin_port = htons(e->icp_port);
	E = &e->next;
    }

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
neighborsUdpPing(protodispatch_data * proto)
{
    char *host = proto->request->host;
    char *url = proto->url;
    StoreEntry *entry = proto->entry;
    const ipcache_addrs *ia = NULL;
    struct sockaddr_in to_addr;
    edge *e = NULL;
    int i;
    MemObject *mem = entry->mem_obj;
    int reqnum = 0;
    int flags;
    icp_common_t *query;

    mem->e_pings_n_pings = 0;
    mem->e_pings_n_acks = 0;
    mem->e_pings_first_miss = NULL;
    mem->w_rtt = 0;
    mem->start_ping = current_time;

    if (friends.edges_head == NULL)
	return 0;
    if (theOutIcpConnection < 0) {
	debug(15, 0, "neighborsUdpPing: There is no ICP socket!\n");
	debug(15, 0, "Cannot query neighbors for '%s'.\n", url);
	debug(15, 0, "Check 'icp_port' in your config file\n");
	fatal_dump(NULL);
    }
    for (i = 0, e = friends.first_ping; i++ < friends.n; e = e->next) {
	if (entry->swap_status != NO_SWAP)
	    fatal_dump("neighborsUdpPing: bad swap_status");
	if (e == (edge *) NULL)
	    e = friends.edges_head;
	debug(15, 5, "neighborsUdpPing: Edge %s\n", e->host);

	/* skip any cache where we failed to connect() w/in the last 60s */
	if (squid_curtime - e->last_fail_time < 60)
	    continue;

	if (!edgeWouldBePinged(e, proto->request))
	    continue;		/* next edge */
	if (e->options & NEIGHBOR_NO_QUERY)
	    continue;
	/* the case below seems strange, but can happen if the
	 * URL host is on the other side of a firewall */
	if (e->type == EDGE_SIBLING)
	    if (!BIT_TEST(proto->request->flags, REQ_HIERARCHICAL))
		continue;

	debug(15, 4, "neighborsUdpPing: pinging cache %s for '%s'\n",
	    e->host, url);

	if (BIT_TEST(entry->flag, KEY_PRIVATE))
	    reqnum = atoi(entry->key);
	else
	    reqnum = getKeyCounter();
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
		if (!BIT_TEST(proto->request->flags, REQ_NOCACHE))
		    if (e->icp_version == ICP_VERSION_2)
			flags |= ICP_FLAG_HIT_OBJ;
	    query = icpCreateMessage(ICP_OP_QUERY, flags, url, reqnum, 0);
	    icpUdpSend(theOutIcpConnection,
		&e->in_addr,
		query,
		LOG_TAG_NONE,
		PROTO_NONE);
	}

	if (e->mcast_ttl > 0) {
	    /* XXX kill us off, so Squid won't expect a reply */
	    e->stats.ack_deficit = HIER_MAX_DEFICIT;
	} else {
	    e->stats.ack_deficit++;
	}
	e->stats.pings_sent++;

	debug(15, 3, "neighborsUdpPing: %s: ack_deficit = %d\n",
	    e->host, e->stats.ack_deficit);

	if (neighborUp(e)) {
	    /* its alive, expect a reply from it */
	    mem->e_pings_n_pings++;
	} else {
	    /* Neighbor is dead; ping it anyway, but don't expect a reply */
	    /* log it once at the threshold */
	    if ((e->stats.ack_deficit == HIER_MAX_DEFICIT)) {
		debug(15, 0, "Detected DEAD %s: %s/%d/%d\n",
		    e->type == EDGE_SIBLING ? "SIBLING" : "PARENT",
		    e->host, e->http_port, e->icp_port);
	    }
	}
	friends.first_ping = e->next;
    }

    /* only do source_ping if we have neighbors */
    if (friends.n) {
	if (!proto->source_ping) {
	    debug(15, 6, "neighborsUdpPing: Source Ping is disabled.\n");
	} else if ((ia = ipcache_gethostbyname(host, IP_BLOCKING_LOOKUP))) {
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
    return mem->e_pings_n_pings;
}

static void
neighborAlive(edge * e, const MemObject * mem, const icp_common_t * header)
{
    int rtt;
    int n;
    /* Neighbor is alive, reset the ack deficit */
    if (e->stats.ack_deficit >= HIER_MAX_DEFICIT) {
	debug(15, 0, "Detected REVIVED %s: %s/%d/%d\n",
	    e->type == EDGE_PARENT ? "PARENT" : "SIBLING",
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
neighborCountIgnored(edge * e, icp_opcode op_unused)
{
    if (e == NULL)
	return;
    e->stats.ignored_replies++;
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
    edge *e = NULL;
    MemObject *mem = entry->mem_obj;
    int w_rtt;
    HttpStateData *httpState = NULL;
    neighbor_t ntype = EDGE_NONE;
    char *opcode_d;
    icp_opcode opcode = (icp_opcode) header->opcode;

    debug(15, 6, "neighborsUdpAck: opcode %d '%s'\n", (int) opcode, url);
    if ((e = whichEdge(from)))
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
    mem->e_pings_n_acks++;
    if (e)
	ntype = neighborType(e, mem->request);
    if (opcode == ICP_OP_SECHO) {
	/* Received source-ping reply */
	if (e) {
	    debug(15, 1, "Ignoring SECHO from neighbor %s\n", e->host);
	    neighborCountIgnored(e, opcode);
	} else {
	    /* if we reach here, source-ping reply is the first 'parent',
	     * so fetch directly from the source */
	    debug(15, 6, "Source is the first to respond.\n");
	    hierarchyNote(entry->mem_obj->request,
		HIER_SOURCE_FASTEST,
		0,
		fqdnFromAddr(from->sin_addr));
	    entry->ping_status = PING_DONE;
	    protoStart(0, entry, NULL, entry->mem_obj->request);
	    return;
	}
    } else if (opcode == ICP_OP_HIT_OBJ) {
	if (e == NULL) {
	    debug(15, 0, "Ignoring ICP_OP_HIT_OBJ from non-neighbor %s\n",
		inet_ntoa(from->sin_addr));
	} else if (entry->object_len != 0) {
	    debug(15, 1, "Too late UDP_HIT_OBJ '%s'?\n", entry->url);
	} else {
	    if (e->options & NEIGHBOR_PROXY_ONLY)
		storeReleaseRequest(entry);
	    protoCancelTimeout(0, entry);
	    entry->ping_status = PING_DONE;
	    httpState = xcalloc(1, sizeof(HttpStateData));
	    httpState->entry = entry;
	    httpProcessReplyHeader(httpState, data, data_sz);
	    storeAppend(entry, data, data_sz);
	    hierarchyNote(entry->mem_obj->request,
		ntype == EDGE_PARENT ? HIER_PARENT_UDP_HIT_OBJ : HIER_SIBLING_UDP_HIT_OBJ,
		0,
		e->host);
	    storeComplete(entry);	/* This might release entry! */
	    if (httpState->reply_hdr)
		put_free_8k_page(httpState->reply_hdr);
	    safe_free(httpState);
	    return;
	}
    } else if (opcode == ICP_OP_HIT) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring HIT from non-neighbor %s\n",
		inet_ntoa(from->sin_addr));
	} else {
	    hierarchyNote(entry->mem_obj->request,
		ntype == EDGE_PARENT ? HIER_PARENT_HIT : HIER_SIBLING_HIT,
		0,
		e->host);
	    entry->ping_status = PING_DONE;
	    protoStart(0, entry, e, entry->mem_obj->request);
	    return;
	}
    } else if (opcode == ICP_OP_DECHO) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring DECHO from non-neighbor %s\n",
		inet_ntoa(from->sin_addr));
	} else if (ntype == EDGE_SIBLING) {
	    debug_trap("neighborsUdpAck: Found non-ICP cache as SIBLING\n");
	    debug_trap("neighborsUdpAck: non-ICP neighbors must be a PARENT\n");
	} else {
	    w_rtt = tvSubMsec(mem->start_ping, current_time) / e->weight;
	    if (mem->w_rtt == 0 || w_rtt < mem->w_rtt) {
		mem->e_pings_first_miss = e;
		mem->w_rtt = w_rtt;
	    }
	}
    } else if (opcode == ICP_OP_MISS) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring MISS from non-neighbor %s\n",
		inet_ntoa(from->sin_addr));
	} else if (ntype == EDGE_PARENT) {
	    w_rtt = tvSubMsec(mem->start_ping, current_time) / e->weight;
	    if (mem->w_rtt == 0 || w_rtt < mem->w_rtt) {
		mem->e_pings_first_miss = e;
		mem->w_rtt = w_rtt;
	    }
	}
    } else if (opcode == ICP_OP_DENIED) {
	if (e == NULL) {
	    debug(15, 1, "Ignoring DENIED from non-neighbor %s\n",
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
    } else if (opcode == ICP_OP_RELOADING) {
	if (e)
	    debug(15, 3, "neighborsUdpAck: %s is RELOADING\n", e->host);
    } else {
	debug(15, 0, "neighborsUdpAck: Unexpected ICP reply: %s\n", opcode_d);
    }
    if (mem->e_pings_n_acks == mem->e_pings_n_pings) {
	entry->ping_status = PING_DONE;
	debug(15, 6, "neighborsUdpAck: All replies received.\n");
	/* pass in fd=0 here so protoStart() looks up the real FD
	 * and resets the timeout handler */
	getFromDefaultSource(0, entry);
	return;
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
    edge *e = NULL;
    const char *me = getMyHostname();
    if (!strcmp(host, me) && http_port == Config.Port.http) {
	debug(15, 0, "neighborAdd: skipping cache_host %s %s/%d/%d\n",
	    type, host, http_port, icp_port);
	return;
    }
    e = xcalloc(1, sizeof(edge));
    e->http_port = http_port;
    e->icp_port = icp_port;
    e->mcast_ttl = mcast_ttl;
    e->options = options;
    e->weight = weight;
    e->host = xstrdup(host);
    e->pinglist = NULL;
    e->typelist = NULL;
    e->acls = NULL;
    e->icp_version = ICP_VERSION_CURRENT;
    e->type = parseNeighborType(type);

    /* Append edge */
    if (!friends.edges_head)
	friends.edges_head = e;
    if (friends.edges_tail)
	friends.edges_tail->next = e;
    friends.edges_tail = e;
    friends.n++;
}

void
neighborAddDomainPing(const char *host, const char *domain)
{
    struct _domain_ping *l = NULL;
    struct _domain_ping **L = NULL;
    edge *e;
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
    edge *e;
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
    edge *e;
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
    if (a->type == ACL_SRC_IP) {
	debug(15, 0, "%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(15, 0, "neighborAddAcl: 'src' ALC's not supported for 'cache_host_acl'\n");
	xfree(L);
	return;
    }
    L->acl = a;
    for (Tail = &(e->acls); *Tail; Tail = &((*Tail)->next));
    *Tail = L;
}

edge *
neighborFindByName(const char *name)
{
    edge *e = NULL;
    for (e = friends.edges_head; e; e = e->next) {
	if (!strcasecmp(name, e->host))
	    break;
    }
    return e;
}

static neighbor_t
parseNeighborType(const char *s)
{
    if (!strcasecmp(s, "parent"))
	return EDGE_PARENT;
    if (!strcasecmp(s, "neighbor"))
	return EDGE_SIBLING;
    if (!strcasecmp(s, "neighbour"))
	return EDGE_SIBLING;
    if (!strcasecmp(s, "sibling"))
	return EDGE_SIBLING;
    debug(15, 0, "WARNING: Unknown neighbor type: %s\n", s);
    return EDGE_SIBLING;
}

int
neighborUp(edge * e)
{
    if (e->last_fail_time)
	if (squid_curtime - e->last_fail_time < (time_t) 60)
	    return 0;
    if (e->stats.ack_deficit > HIER_MAX_DEFICIT)
	return 0;
    return 1;
}

void
edgeDestroy(edge * e)
{
    if (e == NULL)
	return;
    safe_free(e->host);
    safe_free(e);
}
