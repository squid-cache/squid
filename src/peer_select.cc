/*
 * $Id: peer_select.cc,v 1.1 1997/02/26 03:08:52 wessels Exp $
 *
 * DEBUG: section 44    Peer Selection Algorithm
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

#define OUTSIDE_FIREWALL 0
#define INSIDE_FIREWALL  1
#define NO_FIREWALL      2

/* for debugging */
static char *firewall_desc_str[] =
{
    "OUTSIDE_FIREWALL",
    "INSIDE_FIREWALL",
    "NO_FIREWALL"
};

int
matchIpList(const ipcache_addrs * ia, ip_acl * ip_list)
{
    int i;
    if (ip_list == NULL)
	return 0;
    for (i = 0; i < ia->count; i++) {
	if (ip_access_check(ia->in_addrs[i], ip_list) == IP_DENY)
	    return 1;
    }
    return 0;
}

static int
matchLocalDomain(const char *host)
{
    const wordlist *s = NULL;
    for (s = Config.local_domain_list; s; s = s->next) {
	if (matchDomainName(s->key, host))
	    return 1;
    }
    return 0;
}

int
peerSelectDirect(request_t * request)
{
    const ipcache_addrs *ia = ipcache_gethostbyname(request->host, 0);
    if (ia && matchIpList(ia, Config.firewall_ip_list))
	return DIRECT_MAYBE;	/* or DIRECT_YES */
    if (!matchInsideFirewall(request->host))
	return DIRECT_NO;
    if (ia && matchIpList(ia, Config.local_ip_list))
	return DIRECT_YES;
    if (matchLocalDomain(request->host))
	return DIRECT_YES;
    if (ia == NULL)
	return DIRECT_NO;
    return DIRECT_MAYBE;
}

int
peerSelectIcpPing(request_t * request, int direct, StoreEntry * entry)
{
    if (entry->ping_status != PING_NONE)
	return 0;
    if (direct == DIRECT_YES)
	fatal_dump("direct == DIRECT_YES");
    if (!BIT_TEST(entry->flag, HIERARCHICAL) && direct != DIRECT_NO)
	return 0;
    if (Config.singleParentBypass && !Config.sourcePing)
	if (getSingleParent(request))
	    return 0;
    if (BIT_TEST(entry->flag, KEY_PRIVATE) && !neighbors_do_private_keys)
	if (direct != DIRECT_NO)
	    return 0;
    return neighborsCount(request);
}


peer *
peerGetSomeParent(request_t * request, hier_code * code)
{
    peer *p;
    if (request->method == METHOD_CONNECT)
	if ((p = Config.sslProxy)) {
	    *code = HIER_SSL_PARENT;
	    return p;
	}
    if (request->method != METHOD_GET)
	if ((p = Config.passProxy)) {
	    *code = HIER_PASS_PARENT;
	    return p;
	}
    if ((p = getDefaultParent(request))) {
	*code = HIER_DEFAULT_PARENT;
	return p;
    }
    if ((p = getSingleParent(request))) {
	*code = HIER_SINGLE_PARENT;
	return p;
    }
    if ((p = getRoundRobinParent(request))) {
	*code = HIER_ROUNDROBIN_PARENT;
	return p;
    }
    if ((p = getFirstUpParent(request))) {
	*code = HIER_FIRSTUP_PARENT;
	return p;
    }
    return NULL;
}

void
peerSelect(int fd, request_t * request, StoreEntry * entry)
{
    peer *p;
    hier_code code;
    int direct = peerSelectDirect(request);
    debug(44,3,"peerSelect: '%s'\n", entry->url);
    if (direct == DIRECT_YES) {
        debug(44,3,"peerSelect: direct == DIRECT_YES --> HIER_DIRECT\n");
	hierarchyNote(request, HIER_DIRECT, 0, request->host);
	protoStart(fd, entry, NULL, request);
	return;
    }
    if (peerSelectIcpPing(request, direct, entry)) {
        debug(44,3,"peerSelect: Doing ICP pings\n");
	/* call neighborUdpPing and start timeout routine */
	if (neighborsUdpPing(request, entry)) {
	    entry->ping_status = PING_WAITING;
	    commSetSelect(fd,
		COMM_SELECT_TIMEOUT,
		(PF) getFromDefaultSource,
		(void *) entry,
		Config.neighborTimeout);
	    return;
	}
	debug_trap("peerSelect: neighborsUdpPing returned 0");
    }
    if ((p = peerGetSomeParent(request, &code))) {
        debug(44,3,"peerSelect: Got some parent %s/%s\n",
		hier_strings[code], p->host);
	hierarchyNote(request, code, 0, p->host);
	protoStart(fd, entry, p, request);
    }
}

/*
 * return 0 if the host is outside the firewall (no domains matched), and
 * return 1 if the host is inside the firewall or no domains at all.
 */
int
matchInsideFirewall(const char *host)
{
    const wordlist *s = Config.inside_firewall_list;
    const char *key = NULL;
    int result = NO_FIREWALL;
    struct in_addr addr;
    if (!s && !Config.firewall_ip_list)
	/* no firewall goop, all hosts are "inside" the firewall */
	return NO_FIREWALL;
    for (; s; s = s->next) {
	key = s->key;
	if (!strcasecmp(key, "none"))
	    /* no domains are inside the firewall, all domains are outside */
	    return OUTSIDE_FIREWALL;
	if (*key == '!') {
	    key++;
	    result = OUTSIDE_FIREWALL;
	} else {
	    result = INSIDE_FIREWALL;
	}
	if (matchDomainName(key, host))
	    return result;
    }
    /* Check for dotted-quads */
    if (Config.firewall_ip_list) {
	if ((addr.s_addr = inet_addr(host)) != inaddr_none) {
	    if (ip_access_check(addr, Config.firewall_ip_list) == IP_DENY)
		return INSIDE_FIREWALL;
	}
    }
    /* all through the list and no domains matched, this host must
     * not be inside the firewall, it must be outside */
    return OUTSIDE_FIREWALL;
}
