
/*
 * $Id: peer_select.cc,v 1.147 2007/04/30 16:56:09 wessels Exp $
 *
 * DEBUG: section 44    Peer Selection Algorithm
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "event.h"
#include "PeerSelectState.h"
#include "Store.h"
#include "ICP.h"
#include "HttpRequest.h"
#include "ACLChecklist.h"
#include "htcp.h"
#include "forward.h"

const char *hier_strings[] =
    {
        "NONE",
        "DIRECT",
        "SIBLING_HIT",
        "PARENT_HIT",
        "DEFAULT_PARENT",
        "SINGLE_PARENT",
        "FIRST_UP_PARENT",
        "FIRST_PARENT_MISS",
        "CLOSEST_PARENT_MISS",
        "CLOSEST_PARENT",
        "CLOSEST_DIRECT",
        "NO_DIRECT_FAIL",
        "SOURCE_FASTEST",
        "ROUNDROBIN_PARENT",
#if USE_CACHE_DIGESTS
        "CD_PARENT_HIT",
        "CD_SIBLING_HIT",
#endif
#if USE_CARP
        "CARP",
#endif
        "ANY_PARENT",
        "INVALID CODE"
    };

static struct
{
    int timeouts;
}

PeerStats;

static const char *DirectStr[] =
    {
        "DIRECT_UNKNOWN",
        "DIRECT_NO",
        "DIRECT_MAYBE",
        "DIRECT_YES"
    };

static void peerSelectFoo(ps_state *);
static void peerPingTimeout(void *data);
static void peerSelectCallback(ps_state * psstate);
static IRCB peerHandlePingReply;
static void peerSelectStateFree(ps_state * psstate);
static void peerIcpParentMiss(peer *, icp_common_t *, ps_state *);
#if USE_HTCP
static void peerHtcpParentMiss(peer *, htcpReplyData *, ps_state *);
static void peerHandleHtcpReply(peer *, peer_t, htcpReplyData *, void *);
#endif
static int peerCheckNetdbDirect(ps_state * psstate);
static void peerGetSomeNeighbor(ps_state *);
static void peerGetSomeNeighborReplies(ps_state *);
static void peerGetSomeDirect(ps_state *);
static void peerGetSomeParent(ps_state *);
static void peerGetAllParents(ps_state *);
static void peerAddFwdServer(FwdServer **, peer *, hier_code);

CBDATA_CLASS_INIT(ps_state);

static void
peerSelectStateFree(ps_state * psstate)
{
    if (psstate->acl_checklist) {
        debugs(44, 1, "calling aclChecklistFree() from peerSelectStateFree");
        delete (psstate->acl_checklist);
    }

    HTTPMSGUNLOCK(psstate->request);

    if (psstate->entry) {
        assert(psstate->entry->ping_status != PING_WAITING);
        psstate->entry->unlock();
        psstate->entry = NULL;
    }

    cbdataFree(psstate);
}

static int
peerSelectIcpPing(HttpRequest * request, int direct, StoreEntry * entry)
{
    int n;
    assert(entry);
    assert(entry->ping_status == PING_NONE);
    assert(direct != DIRECT_YES);
    debugs(44, 3, "peerSelectIcpPing: " << entry->url()  );

    if (!request->flags.hierarchical && direct != DIRECT_NO)
        return 0;

    if (EBIT_TEST(entry->flags, KEY_PRIVATE) && !neighbors_do_private_keys)
        if (direct != DIRECT_NO)
            return 0;

    n = neighborsCount(request);

    debugs(44, 3, "peerSelectIcpPing: counted " << n << " neighbors");

    return n;
}


void
peerSelect(HttpRequest * request,
           StoreEntry * entry,
           PSC * callback,
           void *callback_data)
{
    ps_state *psstate;

    if (entry)
        debugs(44, 3, "peerSelect: " << entry->url()  );
    else
        debugs(44, 3, "peerSelect: " << RequestMethodStr[request->method]);

    psstate = new ps_state;

    psstate->request = HTTPMSGLOCK(request);

    psstate->entry = entry;

    psstate->callback = callback;

    psstate->callback_data = cbdataReference(callback_data);

    psstate->direct = DIRECT_UNKNOWN;

#if USE_CACHE_DIGESTS

    request->hier.peer_select_start = current_time;

#endif

    if (psstate->entry)
        psstate->entry->lock()

        ;

    peerSelectFoo(psstate);
}

static void
peerCheckNeverDirectDone(int answer, void *data)
{
    ps_state *psstate = (ps_state *) data;
    psstate->acl_checklist = NULL;
    debugs(44, 3, "peerCheckNeverDirectDone: " << answer);
    psstate->never_direct = answer ? 1 : -1;
    peerSelectFoo(psstate);
}

static void
peerCheckAlwaysDirectDone(int answer, void *data)
{
    ps_state *psstate = (ps_state *)data;
    psstate->acl_checklist = NULL;
    debugs(44, 3, "peerCheckAlwaysDirectDone: " << answer);
    psstate->always_direct = answer ? 1 : -1;
    peerSelectFoo(psstate);
}

static void
peerSelectCallback(ps_state * psstate)
{
    StoreEntry *entry = psstate->entry;
    FwdServer *fs = psstate->servers;
    PSC *callback;
    void *cbdata;

    if (entry) {
        debugs(44, 3, "peerSelectCallback: " << entry->url()  );

        if (entry->ping_status == PING_WAITING)
            eventDelete(peerPingTimeout, psstate);

        entry->ping_status = PING_DONE;
    }

    if (fs == NULL) {
        debugs(44, 1, "Failed to select source for '" << entry->url() << "'" );
        debugs(44, 1, "  always_direct = " << psstate->always_direct  );
        debugs(44, 1, "   never_direct = " << psstate->never_direct  );
        debugs(44, 1, "       timedout = " << psstate->ping.timedout  );
    }

    psstate->ping.stop = current_time;
    psstate->request->hier.ping = psstate->ping;
    callback = psstate->callback;
    psstate->callback = NULL;

    if (cbdataReferenceValidDone(psstate->callback_data, &cbdata)) {
        psstate->servers = NULL;
        callback(fs, cbdata);
    }

    peerSelectStateFree(psstate);
}

static int
peerCheckNetdbDirect(ps_state * psstate)
{
    peer *p;
    int myrtt;
    int myhops;

    if (psstate->direct == DIRECT_NO)
        return 0;

    myrtt = netdbHostRtt(psstate->request->host);

    debugs(44, 3, "peerCheckNetdbDirect: MY RTT = " << myrtt << " msec");
    debugs(44, 3, "peerCheckNetdbDirect: minimum_direct_rtt = " << Config.minDirectRtt << " msec");


    if (myrtt && myrtt <= Config.minDirectRtt)
        return 1;

    myhops = netdbHostHops(psstate->request->host);

    debugs(44, 3, "peerCheckNetdbDirect: MY hops = " << myhops);
    debugs(44, 3, "peerCheckNetdbDirect: minimum_direct_hops = " << Config.minDirectHops);


    if (myhops && myhops <= Config.minDirectHops)
        return 1;

    p = whichPeer(&psstate->closest_parent_miss);

    if (p == NULL)
        return 0;

    debugs(44, 3, "peerCheckNetdbDirect: closest_parent_miss RTT = " << psstate->ping.p_rtt << " msec");

    if (myrtt && myrtt <= psstate->ping.p_rtt)
        return 1;

    return 0;
}

static void
peerSelectFoo(ps_state * ps)
{
    StoreEntry *entry = ps->entry;
    HttpRequest *request = ps->request;
    debugs(44, 3, "peerSelectFoo: '" << RequestMethodStr[request->method] << " " << request->host << "'");

    if (ps->direct == DIRECT_UNKNOWN) {
        if (ps->always_direct == 0 && Config.accessList.AlwaysDirect) {
            ps->acl_checklist = aclChecklistCreate(
                                    Config.accessList.AlwaysDirect,
                                    request,
                                    NULL);		/* ident */
            ps->acl_checklist->nonBlockingCheck(peerCheckAlwaysDirectDone,
                                                ps);
            return;
        } else if (ps->always_direct > 0) {
            ps->direct = DIRECT_YES;
        } else if (ps->never_direct == 0 && Config.accessList.NeverDirect) {
            ps->acl_checklist = aclChecklistCreate(
                                    Config.accessList.NeverDirect,
                                    request,
                                    NULL);		/* ident */
            ps->acl_checklist->nonBlockingCheck(peerCheckNeverDirectDone,
                                                ps);
            return;
        } else if (ps->never_direct > 0) {
            ps->direct = DIRECT_NO;
        } else if (request->flags.accelerated) {
            ps->direct = DIRECT_NO;
        } else if (request->flags.loopdetect) {
            ps->direct = DIRECT_YES;
        } else if (peerCheckNetdbDirect(ps)) {
            ps->direct = DIRECT_YES;
        } else {
            ps->direct = DIRECT_MAYBE;
        }

        debugs(44, 3, "peerSelectFoo: direct = " << DirectStr[ps->direct]);
    }

    if (entry == NULL) {
        (void) 0;
    } else if (entry->ping_status == PING_NONE) {
        peerGetSomeNeighbor(ps);

        if (entry->ping_status == PING_WAITING)
            return;
    } else if (entry->ping_status == PING_WAITING) {
        peerGetSomeNeighborReplies(ps);
        entry->ping_status = PING_DONE;
    }

    switch (ps->direct) {

    case DIRECT_YES:
        peerGetSomeDirect(ps);
        break;

    case DIRECT_NO:
        peerGetSomeParent(ps);
        peerGetAllParents(ps);
        break;

    default:

        if (Config.onoff.prefer_direct)
            peerGetSomeDirect(ps);

        if (request->flags.hierarchical || !Config.onoff.nonhierarchical_direct)
            peerGetSomeParent(ps);

        if (!Config.onoff.prefer_direct)
            peerGetSomeDirect(ps);

        break;
    }

    peerSelectCallback(ps);
}

/*
 * peerGetSomeNeighbor
 * 
 * Selects a neighbor (parent or sibling) based on one of the
 * following methods:
 *      Cache Digests
 *      CARP
 *      Netdb RTT estimates
 *      ICP/HTCP queries
 */
static void
peerGetSomeNeighbor(ps_state * ps)
{
    StoreEntry *entry = ps->entry;
    HttpRequest *request = ps->request;
    peer *p;
    hier_code code = HIER_NONE;
    assert(entry->ping_status == PING_NONE);

    if (ps->direct == DIRECT_YES) {
        entry->ping_status = PING_DONE;
        return;
    }

#if USE_CACHE_DIGESTS
    if ((p = neighborsDigestSelect(request))) {
        if (neighborType(p, request) == PEER_PARENT)
            code = CD_PARENT_HIT;
        else
            code = CD_SIBLING_HIT;
    } else
#endif
        if ((p = netdbClosestParent(request))) {
            code = CLOSEST_PARENT;
        } else if (peerSelectIcpPing(request, ps->direct, entry)) {
            debugs(44, 3, "peerSelect: Doing ICP pings");
            ps->ping.start = current_time;
            ps->ping.n_sent = neighborsUdpPing(request,
                                               entry,
                                               peerHandlePingReply,
                                               ps,
                                               &ps->ping.n_replies_expected,
                                               &ps->ping.timeout);

            if (ps->ping.n_sent == 0)
                debugs(44, 0, "WARNING: neighborsUdpPing returned 0");
                debugs(44, 3, "peerSelect: " << ps->ping.n_replies_expected <<
                       " ICP replies expected, RTT " << ps->ping.timeout <<
                       " msec");


            if (ps->ping.n_replies_expected > 0) {
                entry->ping_status = PING_WAITING;
                eventAdd("peerPingTimeout",
                         peerPingTimeout,
                         ps,
                         0.001 * ps->ping.timeout,
                         0);
                return;
            }
        }

    if (code != HIER_NONE) {
        assert(p);
        debugs(44, 3, "peerSelect: " << hier_strings[code] << "/" << p->host);
        peerAddFwdServer(&ps->servers, p, code);
    }

    entry->ping_status = PING_DONE;
}

/*
 * peerGetSomeNeighborReplies
 * 
 * Selects a neighbor (parent or sibling) based on ICP/HTCP replies.
 */
static void
peerGetSomeNeighborReplies(ps_state * ps)
{
    HttpRequest *request = ps->request;
    peer *p = NULL;
    hier_code code = HIER_NONE;
    assert(ps->entry->ping_status == PING_WAITING);
    assert(ps->direct != DIRECT_YES);

    if (peerCheckNetdbDirect(ps)) {
        code = CLOSEST_DIRECT;
        debugs(44, 3, "peerSelect: " << hier_strings[code] << "/" << request->host);
        peerAddFwdServer(&ps->servers, NULL, code);
        return;
    }

    if ((p = ps->hit)) {
        code = ps->hit_type == PEER_PARENT ? PARENT_HIT : SIBLING_HIT;
    } else
#if ALLOW_SOURCE_PING
        if ((p = ps->secho)) {
            code = SOURCE_FASTEST;
        } else
#endif
            if (ps->closest_parent_miss.sin_addr.s_addr != any_addr.s_addr) {
                p = whichPeer(&ps->closest_parent_miss);
                code = CLOSEST_PARENT_MISS;
            } else if (ps->first_parent_miss.sin_addr.s_addr != any_addr.s_addr) {
                p = whichPeer(&ps->first_parent_miss);
                code = FIRST_PARENT_MISS;
            }

    if (p && code != HIER_NONE) {
        debugs(44, 3, "peerSelect: " << hier_strings[code] << "/" << p->host);
        peerAddFwdServer(&ps->servers, p, code);
    }
}


/*
 * peerGetSomeDirect
 * 
 * Simply adds a 'direct' entry to the FwdServers list if this
 * request can be forwarded directly to the origin server
 */
static void
peerGetSomeDirect(ps_state * ps)
{
    if (ps->direct == DIRECT_NO)
        return;

    /* WAIS is not implemented natively */
    if (ps->request->protocol == PROTO_WAIS)
	return;

    peerAddFwdServer(&ps->servers, NULL, HIER_DIRECT);
}

static void
peerGetSomeParent(ps_state * ps)
{
    peer *p;
    HttpRequest *request = ps->request;
    hier_code code = HIER_NONE;
    debugs(44, 3, "peerGetSomeParent: " << RequestMethodStr[request->method] << " " << request->host);

    if (ps->direct == DIRECT_YES)
        return;

    if ((p = getDefaultParent(request))) {
        code = DEFAULT_PARENT;
#if USE_CARP

    } else if ((p = carpSelectParent(request))) {
        code = CARP;
#endif

    } else if ((p = getRoundRobinParent(request))) {
        code = ROUNDROBIN_PARENT;
    } else if ((p = getWeightedRoundRobinParent(request))) {
        code = ROUNDROBIN_PARENT;
    } else if ((p = getFirstUpParent(request))) {
        code = FIRSTUP_PARENT;
    } else if ((p = getAnyParent(request))) {
        code = ANY_OLD_PARENT;
    }

    if (code != HIER_NONE) {
        debugs(44, 3, "peerSelect: " << hier_strings[code] << "/" << p->host);
        peerAddFwdServer(&ps->servers, p, code);
    }
}

/* Adds alive parents. Used as a last resort for never_direct.
 */
static void
peerGetAllParents(ps_state * ps)
{
    peer *p;
    HttpRequest *request = ps->request;
    /* Add all alive parents */

    for (p = Config.peers; p; p = p->next) {
        /* XXX: neighbors.c lacks a public interface for enumerating
         * parents to a request so we have to dig some here..
         */

        if (neighborType(p, request) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, request))
            continue;

        debugs(15, 3, "peerGetAllParents: adding alive parent " << p->host);

        peerAddFwdServer(&ps->servers, p, ANY_OLD_PARENT);
    }

    /* XXX: should add dead parents here, but it is currently
     * not possible to find out which parents are dead or which
     * simply are not configured to handle the request.
     */
    /* Add default parent as a last resort */
    if ((p = getDefaultParent(request))) {
        peerAddFwdServer(&ps->servers, p, DEFAULT_PARENT);
    }
}

static void
peerPingTimeout(void *data)
{
    ps_state *psstate = (ps_state *)data;
    StoreEntry *entry = psstate->entry;

    if (entry)
        debugs(44, 3, "peerPingTimeout: '" << entry->url() << "'" );

    if (!cbdataReferenceValid(psstate->callback_data)) {
        /* request aborted */
        entry->ping_status = PING_DONE;
        cbdataReferenceDone(psstate->callback_data);
        peerSelectStateFree(psstate);
        return;
    }

    PeerStats.timeouts++;
    psstate->ping.timedout = 1;
    peerSelectFoo(psstate);
}

void
peerSelectInit(void)
{
    memset(&PeerStats, '\0', sizeof(PeerStats));
    assert(sizeof(hier_strings) == (HIER_MAX + 1) * sizeof(char *));
}

static void
peerIcpParentMiss(peer * p, icp_common_t * header, ps_state * ps)
{
    int rtt;
    int hops;

    if (Config.onoff.query_icmp) {
        if (header->flags & ICP_FLAG_SRC_RTT) {
            rtt = header->pad & 0xFFFF;
            hops = (header->pad >> 16) & 0xFFFF;

            if (rtt > 0 && rtt < 0xFFFF)
                netdbUpdatePeer(ps->request, p, rtt, hops);

            if (rtt && (ps->ping.p_rtt == 0 || rtt < ps->ping.p_rtt)) {
                ps->closest_parent_miss = p->in_addr;
                ps->ping.p_rtt = rtt;
            }
        }
    }

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (ps->closest_parent_miss.sin_addr.s_addr != any_addr.s_addr)
        return;

    rtt = (tvSubMsec(ps->ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (ps->first_parent_miss.sin_addr.s_addr == any_addr.s_addr ||
            rtt < ps->ping.w_rtt) {
        ps->first_parent_miss = p->in_addr;
        ps->ping.w_rtt = rtt;
    }
}

static void
peerHandleIcpReply(peer * p, peer_t type, icp_common_t * header, void *data)
{
    ps_state *psstate = (ps_state *)data;
    icp_opcode op = header->getOpCode();
    debugs(44, 3, "peerHandleIcpReply: " << icp_opcode_str[op] << " " << psstate->entry->url()  );
#if USE_CACHE_DIGESTS && 0
    /* do cd lookup to count false misses */

    if (p && request)
        peerNoteDigestLookup(request, p,
                             peerDigestLookup(p, request, psstate->entry));

#endif

    psstate->ping.n_recv++;

    if (op == ICP_MISS || op == ICP_DECHO) {
        if (type == PEER_PARENT)
            peerIcpParentMiss(p, header, psstate);
    } else if (op == ICP_HIT) {
        psstate->hit = p;
        psstate->hit_type = type;
        peerSelectFoo(psstate);
        return;
    }

#if ALLOW_SOURCE_PING
    else if (op == ICP_SECHO) {
        psstate->secho = p;
        peerSelectFoo(psstate);
        return;
    }

#endif
    if (psstate->ping.n_recv < psstate->ping.n_replies_expected)
        return;

    peerSelectFoo(psstate);
}

#if USE_HTCP
static void
peerHandleHtcpReply(peer * p, peer_t type, htcpReplyData * htcp, void *data)
{
    ps_state *psstate = (ps_state *)data;
    debugs(44, 3, "peerHandleHtcpReply: " << 
                  (htcp->hit ? "HIT" : "MISS") << " " << 
                  psstate->entry->url()  );
    psstate->ping.n_recv++;

    if (htcp->hit) {
        psstate->hit = p;
        psstate->hit_type = type;
        peerSelectFoo(psstate);
        return;
    }

    if (type == PEER_PARENT)
        peerHtcpParentMiss(p, htcp, psstate);

    if (psstate->ping.n_recv < psstate->ping.n_replies_expected)
        return;

    peerSelectFoo(psstate);
}

static void
peerHtcpParentMiss(peer * p, htcpReplyData * htcp, ps_state * ps)
{
    int rtt;
    int hops;

    if (Config.onoff.query_icmp) {
        if (htcp->cto.rtt > 0) {
            rtt = (int) htcp->cto.rtt * 1000;
            hops = (int) htcp->cto.hops * 1000;
            netdbUpdatePeer(ps->request, p, rtt, hops);

            if (rtt && (ps->ping.p_rtt == 0 || rtt < ps->ping.p_rtt)) {
                ps->closest_parent_miss = p->in_addr;
                ps->ping.p_rtt = rtt;
            }
        }
    }

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (ps->closest_parent_miss.sin_addr.s_addr != any_addr.s_addr)
        return;

    rtt = (tvSubMsec(ps->ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (ps->first_parent_miss.sin_addr.s_addr == any_addr.s_addr ||
            rtt < ps->ping.w_rtt) {
        ps->first_parent_miss = p->in_addr;
        ps->ping.w_rtt = rtt;
    }
}

#endif

static void
peerHandlePingReply(peer * p, peer_t type, protocol_t proto, void *pingdata, void *data)
{
    if (proto == PROTO_ICP)
        peerHandleIcpReply(p, type, (icp_common_t *)pingdata, data);

#if USE_HTCP

    else if (proto == PROTO_HTCP)
        peerHandleHtcpReply(p, type, (htcpReplyData *)pingdata, data);

#endif

    else
        debugs(44, 1, "peerHandlePingReply: unknown protocol_t " << proto);
}

static void
peerAddFwdServer(FwdServer ** FSVR, peer * p, hier_code code)
{
    FwdServer *fs = (FwdServer *)memAllocate(MEM_FWD_SERVER);
    debugs(44, 5, "peerAddFwdServer: adding " << 
                 (p ? p->host : "DIRECT")  << " " << 
                 hier_strings[code]  );
    fs->_peer = cbdataReference(p);
    fs->code = code;

    while (*FSVR)
        FSVR = &(*FSVR)->next;

    *FSVR = fs;
}

void *
ps_state::operator new(size_t)
{
    CBDATA_INIT_TYPE(ps_state);
    return cbdataAlloc(ps_state);
}

ps_state::ps_state() : request (NULL),
        entry (NULL),
        always_direct (0),
        never_direct (0),
        direct (0),
        callback (NULL),
        callback_data (NULL),
        servers (NULL),
        hit(NULL),
        hit_type(PEER_NONE),
#if ALLOW_SOURCE_PING

        secho( NULL),
#endif
        acl_checklist (NULL)
{
    memset(&first_parent_miss, '\0', sizeof(first_parent_miss));
    memset(&closest_parent_miss, '\0', sizeof(closest_parent_miss));
}

ping_data::ping_data() :
        n_sent(0),
        n_recv(0),
        n_replies_expected(0),
        timeout(0),
        timedout(0),
        w_rtt(0),
        p_rtt(0)
{
    start.tv_sec = 0;
    start.tv_usec = 0;
    stop.tv_sec = 0;
    stop.tv_usec = 0;
}
