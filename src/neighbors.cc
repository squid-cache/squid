static char rcsid[] = "$Id: neighbors.cc,v 1.2 1996/02/23 06:56:33 wessels Exp $";
/*
 *  File:         icp.c
 *  Description:  Keeps track of other caches and cache clients
 *  Author:       Peter Danzig, Chuck and Anawat Chankhunthod USC
 *  Created:      Mon May 16 14:18:36 PDT 1994
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

#include "ansihelp.h"
#include "comm.h"
#include "store.h"
#include "icp.h"
#include "proto.h"
#include "neighbors.h"
#include "ipcache.h"
#include "cache_cf.h"
#include "util.h"
#include "disk.h"

static neighbors *friends = NULL;

extern time_t cached_curtime;
extern int unbuffered_logs;	/* main.c */
extern char *tmp_error_buf;	/* main.c */
extern int icpUdpSend _PARAMS((int, char *, icp_common_t *, struct sockaddr_in *, icp_opcode));
extern int getFromOrgSource _PARAMS((int fd, StoreEntry * entry));
extern int getFromCache _PARAMS((int fd, StoreEntry * entry, edge * e));
extern int getFromDefaultSource _PARAMS((int fd, StoreEntry * entry));
extern void fatal_dump _PARAMS((char *));
extern void fatal _PARAMS((char *));

static struct neighbor_cf *Neighbor_cf = NULL;

static icp_common_t echo_hdr;
static short echo_port;
FILE *cache_hierarchy_log = NULL;

static char *hier_strings[] =
{
    "NONE",
    "DIRECT",
    "NEIGHBOR_HIT",
    "PARENT_HIT",
    "SINGLE_PARENT",
    "NO_PARENT_DIRECT",
    "FIRST_PARENT_MISS",
    "LOCAL_IP_DIRECT",
    "DEAD_PARENT",
    "DEAD_NEIGHBOR",
    "REVIVE_PARENT",
    "REVIVE_NEIGHBOR",
    "NO_DIRECT_FAIL",
    "SOURCE_FASTEST",
    "INVALID CODE"
};


edge *whichEdge(header, from)
     icp_common_t *header;
     struct sockaddr_in *from;
{
    int j;
    int port;
    struct in_addr ip;
    edge *e = NULL;

    port = ntohs(from->sin_port);
    ip = from->sin_addr;

    debug(3, "whichEdge: from %s port %d\n", inet_ntoa(ip), port);

    for (e = friends->edges_head; e; e = e->next) {
	for (j = 0; j < e->n_addresses; j++) {
	    if (ip.s_addr == e->addresses[j].s_addr && port == e->udp_port) {
		return e;
	    }
	}
    }
    return (NULL);
}


void hierarchy_log_append(url, code, timeout, cache_host)
     char *url;
     hier_code code;
     int timeout;
     char *cache_host;
{
    static time_t last_time = 0;
    static char time_str[128];
    char *s = NULL;

    if (!cache_hierarchy_log)
	return;

    if (code > HIER_MAX)
	code = HIER_MAX;

    if (emulate_httpd_log) {
	if (cached_curtime != last_time) {
	    s = mkhttpdlogtime(&cached_curtime);
	    strcpy(time_str, s);
	    last_time = cached_curtime;
	}
	if (cache_host) {
	    fprintf(cache_hierarchy_log, "[%s] %s %s%s %s\n",
		time_str,
		url,
		timeout ? "TIMEOUT_" : "",
		hier_strings[code],
		cache_host);
	} else {
	    fprintf(cache_hierarchy_log, "[%s] %s %s%s\n",
		time_str,
		url,
		timeout ? "TIMEOUT_" : "",
		hier_strings[code]);
	}
    } else {
	if (cache_host) {
	    fprintf(cache_hierarchy_log, "%d %s %s%s %s\n",
		(int) cached_curtime,
		url,
		timeout ? "TIMEOUT_" : "",
		hier_strings[code],
		cache_host);
	} else {
	    fprintf(cache_hierarchy_log, "%d %s %s%s\n",
		(int) cached_curtime,
		url,
		timeout ? "TIMEOUT_" : "",
		hier_strings[code]);
	}
    }
    if (unbuffered_logs)
	fflush(cache_hierarchy_log);
}

static int edgeWouldBePinged(e, host)
     edge *e;
     char *host;
{
    int offset;
    dom_list *d = NULL;
    int do_ping = 1;

    if (e->domains == NULL)
	return do_ping;

    do_ping = 0;
    for (d = e->domains; d; d = d->next) {
	if ((offset = strlen(host) - strlen(d->domain)) < 0) {
	    do_ping = !d->do_ping;
	    continue;
	}
	if (strcasecmp(d->domain, host + offset) == 0) {
	    /* found a match, no need to check any more domains */
	    do_ping = d->do_ping;
	    break;
	} else {
	    do_ping = !d->do_ping;
	}
    }
    return do_ping;
}

edge *getSingleParent(host, n)
     char *host;
     int *n;
{
    edge *p = NULL;
    edge *e = NULL;
    int count = 0;

    if (n == NULL && friends->n_parent < 1)
	return NULL;
    for (e = friends->edges_head; e; e = e->next) {
	if (edgeWouldBePinged(e, host)) {
	    count++;
	    if (e->type != is_a_parent) {
		/* we matched a neighbor, not a parent.  There
		 * can be no single parent */
		if (n == NULL)
		    return NULL;
		continue;
	    }
	    if (p) {
		/* already have a parent, this makes the second,
		 * so there can be no single parent */
		if (n == NULL)
		    return NULL;
		continue;
	    }
	    p = e;
	}
    }
    /* Ok, all done checking the edges.  If only one parent matched, then
     * p will already point to it */
    if (n)
	*n = count;
    if (count == 1)
	return p;
    return NULL;
}

edge *getFirstParent(host)
     char *host;
{
    edge *e = NULL;
    if (friends->n_parent < 1)
	return NULL;
    for (e = friends->edges_head; e; e = e->next) {
	if (e->type != is_a_parent)
	    continue;
	if (edgeWouldBePinged(e, host))
	    return e;
    }
    return NULL;
}

edge *getNextEdge(edge * e)
{
    return e->next;
}

edge *getFirstEdge()
{
    return friends->edges_head;
}

void neighbors_install(host, type, ascii_port, udp_port, proxy_only, domains)
     char *host;
     char *type;
     int ascii_port;
     int udp_port;
     int proxy_only;
     dom_list *domains;
{
    edge *e;

    debug(1, "Adding a %s: %s\n", type, host);

    e = (edge *) xcalloc(1, sizeof(edge));

    e->ack_deficit = 0;
    e->ascii_port = ascii_port;
    e->udp_port = udp_port;
    e->proxy_only = proxy_only;
    e->host = xstrdup(host);
    e->domains = domains;
    e->num_pings = 0;
    e->pings_sent = 0;
    e->pings_acked = 0;
    e->neighbor_up = 1;
    e->hits = 0;
    e->misses = 0;

    if (!strcmp(type, "parent")) {
	friends->n_parent++;
	e->type = is_a_parent;
    } else {
	friends->n_neighbor++;
	e->type = is_a_neighbor;
    }

    /* Append edge */
    if (!friends->edges_head)
	friends->edges_head = e;
    if (friends->edges_tail)
	friends->edges_tail->next = e;
    friends->edges_tail = e;

    friends->n++;
}

void neighbors_open(fd)
     int fd;
{
    int j;
    struct sockaddr_in our_socket_name;
    struct sockaddr_in *ap;
    int sock_name_length = sizeof(our_socket_name);
    int log_fd;
    char *fname = NULL;
    char **list = NULL;
    edge *e = NULL;
    struct in_addr *ina = NULL;

    if (getsockname(fd, (struct sockaddr *) &our_socket_name,
	    &sock_name_length) == -1) {
	debug(1, "getsockname(%d,%p,%p) failed.\n",
	    fd, &our_socket_name, &sock_name_length);
    }
    friends->fd = fd;

    /* open log file */
    if ((fname = getHierarchyLogFile())) {
	log_fd = file_open(fname, NULL, O_WRONLY | O_CREAT | O_APPEND);
	if (log_fd < 0) {
	    debug(1, "%s: %s\n", fname, xstrerror());
	    debug(1, "Hierachical logging is disabled.\n");
	} else if (!(cache_hierarchy_log = fdopen(log_fd, "a"))) {
	    debug(1, "%s: %s\n", fname, xstrerror());
	    debug(1, "Hierachical logging is disabled.\n");
	}
    }
    /* Prepare neighbor connections, one at a time */
    for (e = friends->edges_head; e; e = e->next) {
	debug(2, "Finding IP addresses for '%s'\n", e->host);
	if ((list = getAddressList(e->host)) == NULL) {
	    sprintf(tmp_error_buf, "DNS lookup for '%s' failed! Cannot continue.\n",
		e->host);
	    fatal(tmp_error_buf);
	}
	e->n_addresses = 0;
	for (j = 0; *list && j < EDGE_MAX_ADDRESSES; j++) {
	    ina = &e->addresses[j];
	    memcpy(&(ina->s_addr), *list, 4);
	    list++;
	    e->n_addresses++;
	}
	if (e->n_addresses < 1) {
	    sprintf(tmp_error_buf, "No IP addresses found for '%s'; Cannot continue.\n", e->host);
	    fatal(tmp_error_buf);
	}
	for (j = 0; j < e->n_addresses; j++) {
	    debug(2, "--> IP address #%d: %s\n", j, inet_ntoa(e->addresses[j]));
	}
	e->rtt = 1000;

	/* Prepare query packet for future use */
	e->header.opcode = ICP_OP_QUERY;
	e->header.version = ICP_VERSION_CURRENT;
	e->header.length = 0;
	e->header.reqnum = 0;
	memset(e->header.auth, '\0', sizeof(u_num32) * ICP_AUTH_SIZE);
	e->header.shostid = our_socket_name.sin_addr.s_addr;

	ap = &e->in_addr;
	memset(ap, '\0', sizeof(struct sockaddr_in));
	ap->sin_family = AF_INET;
	ap->sin_addr = e->addresses[0];
	ap->sin_port = htons(e->udp_port);

	if (e->type == is_a_parent) {
	    debug(3, "parent_install: host %s addr %s port %d\n",
		e->host, inet_ntoa(ap->sin_addr),
		e->udp_port);
	    e->neighbor_up = 1;
	} else {
	    debug(3, "neighbor_install: host %s addr %s port %d\n",
		e->host, inet_ntoa(ap->sin_addr),
		e->udp_port);
	    e->neighbor_up = 1;
	}

	/* do this only the first time thru */
	if (0 == echo_hdr.opcode) {
	    struct servent *sep;

	    echo_hdr.opcode = ICP_OP_SECHO;
	    echo_hdr.version = ICP_VERSION_CURRENT;
	    echo_hdr.length = 0;
	    echo_hdr.reqnum = 0;
	    memset(echo_hdr.auth, '\0', sizeof(u_num32) * ICP_AUTH_SIZE);
	    echo_hdr.shostid = our_socket_name.sin_addr.s_addr;

	    sep = getservbyname("echo", "udp");
	    echo_port = sep ? sep->s_port : 7;
	}
    }
}

neighbors *neighbors_create()
{
    neighbors *f;

    f = (neighbors *) xcalloc(1, sizeof(neighbors));
    f->n = 0;
    f->n_parent = 0;
    f->n_neighbor = 0;
    f->edges_head = (edge *) NULL;
    f->edges_tail = (edge *) NULL;
    f->first_ping = (edge *) NULL;
    return (friends = f);
}


int neighborsUdpPing(proto)
     protodispatch_data *proto;
{
    char *t = NULL;
    char *host = proto->host;
    char *url = proto->url;
    StoreEntry *entry = proto->entry;
    struct hostent *hep = NULL;
    struct sockaddr_in to_addr;
    edge *e = NULL;
    int i;

    entry->mem_obj->e_pings_n_pings = 0;
    entry->mem_obj->e_pings_n_acks = 0;
    entry->mem_obj->e_pings_first_miss = NULL;

    if (friends->edges_head == (edge *) NULL)
	return 0;

    for (i = 0, e = friends->first_ping; i++ < friends->n; e = e->next) {
	if (e == (edge *) NULL)
	    e = friends->edges_head;
	debug(5, "neighborsUdpPing: Edge %s\n", e->host);

	/* Don't resolve refreshes through neighbors because we don't resolve
	 * misses through neighbors */
	if ((e->type == is_a_neighbor) && (entry->flag & REFRESH_REQUEST))
	    continue;

	/* skip dumb caches where we failed to connect() w/in the last 60s */
	if (e->udp_port == echo_port &&
	    (cached_curtime - e->last_fail_time < 60))
	    continue;

	if (!edgeWouldBePinged(e, host))
	    continue;		/* next edge */

	debug(4, "neighborsUdpPing: pinging cache %s for <URL:%s>\n",
	    e->host, url);

	e->header.reqnum++;

	if (e->udp_port == echo_port) {
	    debug(4, "neighborsUdpPing: Looks like a dumb cache, send DECHO ping\n");
	    icpUdpSend(friends->fd, url, &echo_hdr, &e->in_addr, ICP_OP_DECHO);
	} else {
	    icpUdpSend(friends->fd, url, &e->header, &e->in_addr, ICP_OP_QUERY);
	}

	e->ack_deficit++;
	e->num_pings++;
	e->pings_sent++;

	if (e->ack_deficit < HIER_MAX_DEFICIT) {
	    /* consider it's alive. count it */
	    e->neighbor_up = 1;
	    entry->mem_obj->e_pings_n_pings++;
	} else {
	    /* consider it's dead. send a ping but don't count it. */
	    e->neighbor_up = 0;
	    if (e->ack_deficit > (HIER_MAX_DEFICIT << 1))
		/* do this to prevent wrap around but we still want it
		 * to move a bit so we can debug it easier. */
		e->ack_deficit = HIER_MAX_DEFICIT + 1;
	    debug(6, "cache %s is considered dead but send PING anyway, hope it comes up soon.\n",
		inet_ntoa(e->in_addr.sin_addr));
	    /* log it once at the threshold */
	    if ((e->ack_deficit == HIER_MAX_DEFICIT)) {
		if (e->type == is_a_neighbor) {
		    hierarchy_log_append("Detect: ",
			HIER_DEAD_NEIGHBOR, 0,
			e->host);
		} else {
		    hierarchy_log_append("Detect: ",
			HIER_DEAD_PARENT, 0,
			e->host);
		}
	    }
	}
	friends->first_ping = e->next;
    }

    /* only do source_ping if we have neighbors */
    if (echo_hdr.opcode) {
	if (proto->source_ping && (hep = ipcache_gethostbyname(host))) {
	    debug(6, "neighborsUdpPing: Send to original host\n");
	    debug(6, "neighborsUdpPing: url=%s, host=%s, t=%d\n",
		url, host, t);
	    to_addr.sin_family = AF_INET;
	    memcpy(&to_addr.sin_addr, hep->h_addr, hep->h_length);
	    to_addr.sin_port = echo_port;
	    echo_hdr.reqnum = cached_curtime;
	    debug(6, "neighborsUdpPing - url: %s to url-host %s \n",
		url, inet_ntoa(to_addr.sin_addr));
	    /* send to original site */
	    icpUdpSend(friends->fd, url, &echo_hdr, &to_addr, ICP_OP_SECHO);
	} else {
	    debug(6, "neighborsUdpPing: Source Ping is disabled.\n");
	}
    }
    return (entry->mem_obj->e_pings_n_pings);
}


/* I should attach these records to the entry.  We take the first
 * hit we get our wait until everyone misses.  The timeout handler
 * call needs to nip this shopping list or call one of the misses.
 * 
 * If a hit process is already started, then sobeit
 */
void neighborsUdpAck(fd, url, header, from, entry)
     int fd;
     char *url;
     icp_common_t *header;
     struct sockaddr_in *from;
     StoreEntry *entry;
{
    edge *e = NULL;

    debug(6, "neighborsUdpAck: url=%s (%d chars), header=0x%x, from=0x%x, ent=0x%x\n",
	url, strlen(url), header, from, entry);
    debug(6, "     hdr: opcode=%d, ver=%d, shostid=%x, len=%d, rn=0x%x\n",
	header->opcode, header->version, header->shostid,
	header->length, header->reqnum);
    debug(6, "     from: fam=%d, port=%d, addr=0x%x\n",
	from->sin_family, from->sin_port, from->sin_addr.s_addr);

    /* look up for neighbor/parent entry */
    e = whichEdge(header, from);

    if (e) {
	/* reset the deficit. It's alive now. */
	/* Don't care about exact count. */
	if ((e->ack_deficit >= HIER_MAX_DEFICIT)) {
	    if (e->type == is_a_neighbor) {
		hierarchy_log_append("Detect: ",
		    HIER_REVIVE_NEIGHBOR, 0, e->host);
	    } else {
		hierarchy_log_append("Detect: ",
		    HIER_REVIVE_PARENT, 0, e->host);
	    }
	}
	e->ack_deficit = 0;
	e->neighbor_up = 1;
	e->pings_acked++;
    }
    /* check if someone is already fetching it */
    if (BIT_TEST(entry->flag, REQ_DISPATCHED) || (entry->ping_status != WAITING)) {
	if (entry->ping_status == DONE) {
	    debug(5, "There is already a cache/source dispatched for this object\n");
	    debug(5, "--> <URL:%s>\n", entry->url);
	    debug(5, "--> entry->flag & REQ_DISPATCHED = %d\n",
		BIT_TEST(entry->flag, REQ_DISPATCHED));
	    debug(5, "--> entry->ping_status = %d\n", entry->ping_status);
	} else {
	    debug(5, "The ping already timed out.\n");
	    debug(5, "--> <URL:%s>\n", entry->url);
	    debug(5, "--> entry->flag & REQ_DISPATCHED = %lx\n",
		BIT_TEST(entry->flag, REQ_DISPATCHED));
	    debug(5, "--> entry->ping_status = %d\n", entry->ping_status);
	}
	return;
    }
    debug(6, "neighborsUdpAck - url: %s to us %s \n",
	url, e ? inet_ntoa(e->in_addr.sin_addr) : "url-host");

    if (header->opcode == ICP_OP_SECHO) {
	/* receive ping back from source or from non-cached cache */
	if (e) {
	    debug(6, "Got SECHO from non-cached cache:%s\n",
		inet_ntoa(e->in_addr.sin_addr));
	    debug(6, "This is not supposed to happen.  Ignored.\n");
	} else {
	    /* if we reach here, source is the one has the fastest respond. */
	    /* fetch directly from source */
	    debug(6, "Source is the first to respond.\n");
	    hierarchy_log_append(entry->url,
		HIER_SOURCE_FASTEST,
		0,
		inet_ntoa(from->sin_addr));
	    BIT_SET(entry->flag, REQ_DISPATCHED);
	    entry->ping_status = DONE;
	    getFromOrgSource(0, entry);
	}
	return;
    }
    if (header->opcode == ICP_OP_HIT) {
	/* If an edge is not found, count it as a MISS message. */
	if (!e) {
	    /* count it as a MISS message */
	    entry->mem_obj->e_pings_n_acks++;
	    return;
	}
	/* GOT a HIT here */
	debug(6, "HIT: Getting %s from host: %s\n", entry->url, e->host);
	if (e->type == is_a_neighbor) {
	    hierarchy_log_append(entry->url, HIER_NEIGHBOR_HIT, 0, e->host);
	} else {
	    hierarchy_log_append(entry->url, HIER_PARENT_HIT, 0, e->host);
	}
	BIT_SET(entry->flag, REQ_DISPATCHED);
	entry->ping_status = DONE;
	getFromCache(0, entry, e);
	e->hits++;
	return;
    } else if ((header->opcode == ICP_OP_MISS) || (header->opcode == ICP_OP_DECHO)) {
	/* everytime we get here, count it as a miss */
	entry->mem_obj->e_pings_n_acks++;
	if (e)
	    e->misses++;

	if (header->opcode == ICP_OP_DECHO) {
	    /* receive ping back from non-cached cache */

	    if (e) {
		debug(6, "Got DECHO from non-cached cache:%s\n",
		    inet_ntoa(e->in_addr.sin_addr));
		debug(6, "Good.");

		if (e->type == is_a_parent) {
		    if (entry->mem_obj->e_pings_first_miss == NULL) {
			debug(6, "OK. We got dumb-cached parent as the first miss here.\n");
			entry->mem_obj->e_pings_first_miss = e;
		    }
		} else {
		    debug(6, "Dumb Cached as a neighbor does not make sense.\n");
		    debug(6, "Count it anyway.\n");
		}


	    } else {
		debug(6, "Got DECHO from non-cached cache: But the host is not in the list.\n");
		debug(6, "Count it anyway.\n");
	    }

	} else {
	    /* ICP_OP_MISS from a cache */
	    if ((entry->mem_obj->e_pings_first_miss == NULL) && e && e->type == is_a_parent) {
		entry->mem_obj->e_pings_first_miss = e;

	    }
	}

	if (entry->mem_obj->e_pings_n_acks == entry->mem_obj->e_pings_n_pings) {
	    BIT_SET(entry->flag, REQ_DISPATCHED);
	    entry->ping_status = DONE;
	    debug(6, "Receive MISSes from all neighbors and parents\n");
	    /* pass in fd=0 here so getFromCache() looks up the real FD
	     * and resets the timeout handler */
	    getFromDefaultSource(0, entry);
	    return;
	}
    } else {
	debug(0, "neighborsUdpAck: WHY ARE WE HERE?  header->opcode = %d\n",
	    header->opcode);
    }
}

void neighbors_cf_add(host, type, ascii_port, udp_port, proxy_only)
     char *host;
     char *type;
     int ascii_port;
     int udp_port;
     int proxy_only;
{
    struct neighbor_cf *t, *u;

    t = (struct neighbor_cf *) xcalloc(sizeof(struct neighbor_cf), 1);
    t->host = xstrdup(host);
    t->type = xstrdup(type);
    t->ascii_port = ascii_port;
    t->udp_port = udp_port;
    t->proxy_only = proxy_only;
    t->next = (struct neighbor_cf *) NULL;

    if (Neighbor_cf == (struct neighbor_cf *) NULL) {
	Neighbor_cf = t;
    } else {
	for (u = Neighbor_cf; u->next; u = u->next);
	u->next = t;
    }
}

int neighbors_cf_domain(host, domain)
     char *host;
     char *domain;
{
    struct neighbor_cf *t;
    dom_list *l;
    dom_list **L;

    for (t = Neighbor_cf; t; t = t->next) {
	if (strcmp(t->host, host) == 0)
	    break;
    }

    if (t == NULL)
	return 0;

    l = (dom_list *) xmalloc(sizeof(dom_list));
    l->do_ping = 1;
    if (*domain == '!') {	/* check for !.edu */
	l->do_ping = 0;
	domain++;
    }
    l->domain = xstrdup(domain);
    l->next = NULL;
    for (L = &(t->domains); *L; L = &((*L)->next));
    *L = l;

    return 1;
}

void neighbors_init()
{
    struct neighbor_cf *t, *next;

    for (t = Neighbor_cf; t; t = next) {
	next = t->next;
	if (strncmp(t->host, comm_hostname(), HARVESTHOSTNAMELEN) ||
	    t->ascii_port != getAsciiPortNum()) {
	    neighbors_install(t->host, t->type,
		t->ascii_port, t->udp_port, t->proxy_only,
		t->domains);
	} else {
	    debug(0, "neighbors_init: skipping cache_host %s %s %d %d\n",
		t->type, t->host, t->ascii_port, t->udp_port);
	    debug(0, "neighbors_init: because it seems to be identical to this cached\n");
	}
	xfree(t->host);
	xfree(t->type);
	xfree(t);
    }
}

void neighbors_rotate_log()
{
    int i;
    static char from[MAXPATHLEN];
    static char to[MAXPATHLEN];
    char *fname = NULL;
    int log_fd;

    if ((fname = getHierarchyLogFile()) == NULL)
	return;

    debug(1, "neighbors_rotate_log: Rotating.\n");

    /* Rotate numbers 0 through N up one */
    for (i = getLogfileRotateNumber(); i > 1;) {
	i--;
	sprintf(from, "%s.%d", fname, i - 1);
	sprintf(to, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (getLogfileRotateNumber() > 0) {
	sprintf(to, "%s.%d", fname, 0);
	rename(fname, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    fclose(cache_hierarchy_log);
    log_fd = file_open(fname, NULL, O_WRONLY | O_CREAT | O_APPEND);
    if (log_fd < 0) {
	debug(0, "rotate_logs: %s: %s\n", fname, xstrerror());
	debug(1, "Hierachical logging is disabled.\n");
    } else if ((cache_hierarchy_log = fdopen(log_fd, "a")) == NULL) {
	debug(0, "rotate_logs: %s: %s\n",
	    fname, xstrerror());
	debug(1, "Hierachical logging is disabled.\n");
    }
}
