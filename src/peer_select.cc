/*
 * $Id: peer_select.cc,v 1.3 1997/02/26 20:49:12 wessels Exp $
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

static struct {
	int timeouts;
} PeerStats;

int
peerSelectDirect(request_t * request)
{
    int answer;
    aclCheck_t ch;
    const ipcache_addrs *ia = ipcache_gethostbyname(request->host, 0);
    memset(&ch, '\0', sizeof(aclCheck_t));
    ch.request = requestLink(request);
    ch.dst_addr = ia->in_addrs[ia->cur];
    ch.src_addr = request->client_addr;
    answer = aclCheck(Config.accessList.NeverDirect, &ch);
    requestUnlink(ch.request);
    if (answer)
	return DIRECT_NO;
    answer = aclCheck(Config.accessList.AlwaysDirect, &ch);
    if (answer)
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
    debug(44, 3, "peerSelect: '%s'\n", entry->url);
    if (direct == DIRECT_YES) {
	debug(44, 3, "peerSelect: direct == DIRECT_YES --> HIER_DIRECT\n");
	hierarchyNote(request, HIER_DIRECT, 0, request->host);
	protoStart(fd, entry, NULL, request);
	return;
    }
    if (peerSelectIcpPing(request, direct, entry)) {
	debug(44, 3, "peerSelect: Doing ICP pings\n");
	/* call neighborUdpPing and start timeout routine */
	if (neighborsUdpPing(request, entry)) {
	    entry->ping_status = PING_WAITING;
	    commSetSelect(fd,
		COMM_SELECT_TIMEOUT,
		peerPingTimeout,
		(void *) entry,
		Config.neighborTimeout);
	    return;
	}
	debug_trap("peerSelect: neighborsUdpPing returned 0");
    }
    if ((p = peerGetSomeParent(request, &code))) {
	debug(44, 3, "peerSelect: Got some parent %s/%s\n",
	    hier_strings[code], p->host);
	hierarchyNote(request, code, 0, p->host);
	protoStart(fd, entry, p, request);
    }
}

void
peerPingTimeout(int fd, void *data)
{
	StoreEntry *entry = data;
	debug(44,3,"peerPingTimeout: '%s'\n", entry->url);
	PeerStats.timeouts++;
	peerSelect(fd, entry->mem_obj->request, entry);
}

void
peerSelectInit(void)
{
	memset(&PeerStats, '\0', sizeof(PeerStats));
}
