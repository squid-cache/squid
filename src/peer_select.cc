/*
 * $Id: peer_select.cc,v 1.4 1997/02/27 02:57:13 wessels Exp $
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

typedef struct _peer_ctrl_t {
    int fd;
    request_t *request;
    StoreEntry *entry;
    int always_direct;
    int never_direct;
    int timeout;
} peer_ctrl_t;


static void peerSelect _PARAMS((peer_ctrl_t *));

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
peerSelectStart(int fd, request_t * request, StoreEntry * entry)
{
    peer_ctrl_t *ctrl = xcalloc(1, sizeof(peer_ctrl_t));
    ctrl->request = request;
    ctrl->entry = entry;
    ctrl->fd = fd;
    peerSelect(ctrl);
}

static void
peerCheckNeverDirectDone(int answer, void *data)
{
    peer_ctrl_t *ctrl = data;
    debug(44, 3, "peerCheckNeverDirectDone: %d\n", answer);
    ctrl->never_direct = answer ? 1 : -1;
    peerSelect(ctrl);
}

static void
peerCheckAlwaysDirectDone(int answer, void *data)
{
    peer_ctrl_t *ctrl = data;
    debug(44, 3, "peerCheckAlwaysDirectDone: %d\n", answer);
    ctrl->always_direct = answer ? 1 : -1;
    peerSelect(ctrl);
}

void
peerSelect(peer_ctrl_t * ctrl)
{
    peer *p;
    hier_code code;
    StoreEntry *entry = ctrl->entry;
    request_t *request = ctrl->request;
    int fd = ctrl->fd;
    int direct;
    debug(44, 3, "peerSelect: '%s'\n", entry->url);
    if (ctrl->never_direct == 0) {
	aclNBCheck(Config.accessList.NeverDirect,
	    request,
	    request->client_addr,
	    NULL,		/* user agent */
	    NULL,		/* ident */
	    peerCheckNeverDirectDone,
	    ctrl);
	return;
    } else if (ctrl->never_direct > 0) {
	direct = DIRECT_NO;
    } else if (ctrl->always_direct == 0) {
	aclNBCheck(Config.accessList.AlwaysDirect,
	    request,
	    request->client_addr,
	    NULL,		/* user agent */
	    NULL,		/* ident */
	    peerCheckAlwaysDirectDone,
	    ctrl);
	return;
    } else if (ctrl->always_direct > 0) {
	direct = DIRECT_YES;
    } else {
	direct = DIRECT_MAYBE;
    }
    debug(44, 3, "peerSelect: direct = %d\n", direct);
    if (direct == DIRECT_YES) {
	debug(44, 3, "peerSelect: HIER_DIRECT\n");
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
		(void *) ctrl,
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
    peer_ctrl_t *ctrl = data;
    StoreEntry *entry = ctrl->entry;
    debug(44, 3, "peerPingTimeout: '%s'\n", entry->url);
    PeerStats.timeouts++;
    ctrl->timeout = 1;
    peerSelect(ctrl);
}

void
peerSelectInit(void)
{
    memset(&PeerStats, '\0', sizeof(PeerStats));
}
