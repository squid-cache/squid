/*
 * $Id: peer_select.cc,v 1.5 1997/02/27 06:29:16 wessels Exp $
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

typedef struct {
    request_t *request;
    StoreEntry *entry;
    int always_direct;
    int never_direct;
    PSC callback;
    PSC fail_callback;
    void *callback_data;
    struct {
	struct timeval start;
	int n_sent;
	int n_recv;
	int n_replies_expected;
	int timeout;
	peer *best_parent;
    } ping;
} psctrl_t;


static void peerSelectFoo _PARAMS((psctrl_t *));
static void peerPingTimeout _PARAMS((void *data));
void peerPingComplete _PARAMS((void *data));
static void peerSelectCallbackFail _PARAMS((psctrl_t * ctrl));

int
peerSelectIcpPing(request_t * request, int direct, StoreEntry * entry)
{
    if (entry == NULL)
	return 0;
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
peerSelect(request_t * request,
	StoreEntry *entry,
	PSC callback,
	PSC fail_callback,
	void *callback_data)
{
    psctrl_t *ctrl = xcalloc(1, sizeof(psctrl_t));
    ctrl->request = requestLink(request);
    ctrl->entry = entry;
    ctrl->callback = callback;
    ctrl->fail_callback = fail_callback;
    ctrl->callback_data = callback_data;
    peerSelectFoo(ctrl);
}

static void
peerCheckNeverDirectDone(int answer, void *data)
{
    psctrl_t *ctrl = data;
    debug(44, 3, "peerCheckNeverDirectDone: %d\n", answer);
    ctrl->never_direct = answer ? 1 : -1;
    peerSelectFoo(ctrl);
}

static void
peerCheckAlwaysDirectDone(int answer, void *data)
{
    psctrl_t *ctrl = data;
    debug(44, 3, "peerCheckAlwaysDirectDone: %d\n", answer);
    ctrl->always_direct = answer ? 1 : -1;
    peerSelectFoo(ctrl);
}

static void
peerSelectCallback(psctrl_t * ctrl, peer * p)
{
    if (!ctrl->ping.timeout)
	eventDelete(peerPingTimeout, ctrl);
    ctrl->callback(p, ctrl->callback_data);
    requestUnlink(ctrl->request);
    xfree(ctrl);
}

static void
peerSelectCallbackFail(psctrl_t * ctrl)
{
    request_t *request = ctrl->request;
    char *url = ctrl->entry ? ctrl->entry->url : urlCanonical(request, NULL);
    debug(44, 1, "Failed to select source for '%s'\n", url);
    debug(44, 1, "  always_direct = %d\n", ctrl->always_direct);
    debug(44, 1, "   never_direct = %d\n", ctrl->never_direct);
    debug(44, 1, "        timeout = %d\n", ctrl->ping.timeout);
    ctrl->fail_callback(NULL, ctrl->callback_data);
    requestUnlink(ctrl->request);
    xfree(ctrl);
}

static void
peerSelectFoo(psctrl_t * ctrl)
{
    peer *p;
    hier_code code;
    StoreEntry *entry = ctrl->entry;
    request_t *request = ctrl->request;
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
	hierarchyNote(request, HIER_DIRECT, ctrl->ping.timeout, request->host);
	peerSelectCallback(ctrl, NULL);
	return;
    }
    if (peerSelectIcpPing(request, direct, entry)) {
	if (entry->ping_status != PING_NONE)
		fatal_dump("peerSelectFoo: bad ping_status");
	debug(44, 3, "peerSelect: Doing ICP pings\n");
	ctrl->ping.n_sent = neighborsUdpPing(request,
		entry,
		&ctrl->ping.n_replies_expected);
	if (ctrl->ping.n_sent > 0) {
	    entry->ping_status = PING_WAITING;
	    eventAdd("peerPingTimeout",
		peerPingTimeout,
		ctrl,
		Config.neighborTimeout);
	    ctrl->ping.start = current_time;
	    return;
	}
	debug_trap("peerSelect: neighborsUdpPing returned 0");
    }
    if ((p = ctrl->ping.best_parent)) {
	code = HIER_BEST_PARENT_MISS;
	debug(44, 3, "peerSelect: %s/%s\n", hier_strings[code], p->host);
	hierarchyNote(request, code, ctrl->ping.timeout, p->host);
	peerSelectCallback(ctrl, p);
    } else if (direct != DIRECT_NO) {
	code = HIER_DIRECT;
	debug(44, 3, "peerSelect: %s/%s\n", hier_strings[code], request->host);
	hierarchyNote(request, code, ctrl->ping.timeout, request->host);
	peerSelectCallback(ctrl, NULL);
    } else if ((p = peerGetSomeParent(request, &code))) {
	debug(44, 3, "peerSelect: %s/%s\n", hier_strings[code], p->host);
	hierarchyNote(request, code, ctrl->ping.timeout, p->host);
	peerSelectCallback(ctrl, p);
    } else {
	code = HIER_NO_DIRECT_FAIL;
	hierarchyNote(request, code, ctrl->ping.timeout, NULL);
	peerSelectCallbackFail(ctrl);
    }
}

void
peerPingTimeout(void *data)
{
    psctrl_t *ctrl = data;
    StoreEntry *entry = ctrl->entry;
    debug(44, 3, "peerPingTimeout: '%s'\n", entry->url);
    entry->ping_status = PING_TIMEOUT;
    PeerStats.timeouts++;
    ctrl->ping.timeout = 1;
    peerSelectFoo(ctrl);
}

void
peerPingComplete(void *data)
{
    psctrl_t *ctrl = data;
    StoreEntry *entry = ctrl->entry;
    debug(44, 3, "peerPingComplete: '%s'\n", entry->url);
    entry->ping_status = PING_DONE;
    peerSelectFoo(ctrl);
}

void
peerSelectInit(void)
{
    memset(&PeerStats, '\0', sizeof(PeerStats));
}


void
peerHandleIcpReply(peer * p, neighbor_t type, icp_opcode_t op, void *data)
{
    psctrl_t *ctrl = data;
    int w_rtt;
    request_t *reqeust = ctrl->request;
    ctrl->pings->n_recv++;
    if (op == ICP_OP_MISS || op == ICP_OP_DECHO) {
	if (type == PEER_PARENT) {
	    w_rtt = tvSubMsec(ctrl->ping.start, current_time) / e->weight;
	    if (ctrl->ping.w_rtt == 0 || w_rtt < ctrl->ping.w_rtt) {
		ctrl->ping.best_parent = e;
		ctrl->ping.w_rtt = w_rtt;
	    }
	}
    } else if (op == ICP_OP_HIT || op == ICP_OP_HIT_OBJ) {
	hierarchyNote(request,
	    type == PEER_PARENT ? HIER_PARENT_HIT : HIER_SIBLING_HIT,
	    0,
	    p->host);
	peerSelectCallback(ctrl, p);
	return;
    } else if (op == ICP_OP_SECHO) {
	hierarchyNote(request,
	    HIER_SOURCE_FASTEST,
	    0,
	    request->host
	peerSelectCallback(ctrl, p);
	return;
    }
    if (ctrl->ping.n_recv < ping.n_replies_expected)
	return;
}
