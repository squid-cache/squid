/*
 * DEBUG: section 15    Neighbor Routines
 * AUTHOR: Harvest Derived
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
#include "ProtoPort.h"
#include "acl/FilledChecklist.h"
#include "event.h"
#include "CacheManager.h"
#include "htcp.h"
#include "HttpRequest.h"
#include "ICP.h"
#include "MemObject.h"
#include "PeerDigest.h"
#include "PeerSelectState.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "Store.h"
#include "icmp/net_db.h"
#include "ip/IpAddress.h"
#include "ip/tools.h"

/* count mcast group peers every 15 minutes */
#define MCAST_COUNT_RATE 900

int peerAllowedToUse(const peer *, HttpRequest *);
static int peerWouldBePinged(const peer *, HttpRequest *);
static void neighborRemove(peer *);
static void neighborAlive(peer *, const MemObject *, const icp_common_t *);
#if USE_HTCP
static void neighborAliveHtcp(peer *, const MemObject *, const htcpReplyData *);
#endif
static void neighborCountIgnored(peer *);
static void peerRefreshDNS(void *);
static IPH peerDNSConfigure;
static int peerProbeConnect(peer *);
static CNCB peerProbeConnectDone;
static void peerCountMcastPeersDone(void *data);
static void peerCountMcastPeersStart(void *data);
static void peerCountMcastPeersSchedule(peer * p, time_t when);
static IRCB peerCountHandleIcpReply;

static void neighborIgnoreNonPeer(const IpAddress &, icp_opcode);
static OBJH neighborDumpPeers;
static OBJH neighborDumpNonPeers;
static void dump_peers(StoreEntry * sentry, peer * peers);

static icp_common_t echo_hdr;
static u_short echo_port;

static int NLateReplies = 0;
static peer *first_ping = NULL;

const char *
neighborTypeStr(const peer * p)
{
    if (p->type == PEER_NONE)
        return "Non-Peer";

    if (p->type == PEER_SIBLING)
        return "Sibling";

    if (p->type == PEER_MULTICAST)
        return "Multicast Group";

    return "Parent";
}


peer *
whichPeer(const IpAddress &from)
{
    int j;

    peer *p = NULL;
    debugs(15, 3, "whichPeer: from " << from);

    for (p = Config.peers; p; p = p->next) {
        for (j = 0; j < p->n_addresses; j++) {
            if (from == p->addresses[j] && from.GetPort() == p->icp.port) {
                return p;
            }
        }
    }

    return NULL;
}

peer_t
neighborType(const peer * p, const HttpRequest * request)
{

    const struct _domain_type *d = NULL;

    for (d = p->typelist; d; d = d->next) {
        if (0 == matchDomainName(request->GetHost(), d->domain))
            if (d->type != PEER_NONE)
                return d->type;
    }
#if PEER_MULTICAST_SIBLINGS
    if (p->type == PEER_MULTICAST)
        if (p->options.mcast_siblings)
            return PEER_SIBLING;
#endif

    return p->type;
}

/*
 * peerAllowedToUse
 *
 * this function figures out if it is appropriate to fetch REQUEST
 * from PEER.
 */
int
peerAllowedToUse(const peer * p, HttpRequest * request)
{

    const struct _domain_ping *d = NULL;
    int do_ping = 1;
    assert(request != NULL);

    if (neighborType(p, request) == PEER_SIBLING) {
#if PEER_MULTICAST_SIBLINGS
        if (p->type == PEER_MULTICAST && p->options.mcast_siblings &&
                (request->flags.nocache || request->flags.refresh || request->flags.loopdetect || request->flags.need_validation))
            debugs(15, 2, "peerAllowedToUse(" << p->name << ", " << request->GetHost() << ") : multicast-siblings optimization match");
#endif
        if (request->flags.nocache)
            return 0;

        if (request->flags.refresh)
            return 0;

        if (request->flags.loopdetect)
            return 0;

        if (request->flags.need_validation)
            return 0;
    }

    // CONNECT requests are proxy requests. Not to be forwarded to origin servers.
    // Unless the destination port matches, in which case we MAY perform a 'DIRECT' to this peer.
    if (p->options.originserver && request->method == METHOD_CONNECT && request->port != p->in_addr.GetPort())
        return 0;

    if (p->peer_domain == NULL && p->access == NULL)
        return do_ping;

    do_ping = 0;

    for (d = p->peer_domain; d; d = d->next) {
        if (0 == matchDomainName(request->GetHost(), d->domain)) {
            do_ping = d->do_ping;
            break;
        }

        do_ping = !d->do_ping;
    }

    if (p->peer_domain && 0 == do_ping)
        return do_ping;

    if (p->access == NULL)
        return do_ping;

    ACLFilledChecklist checklist(p->access, request, NULL);
    checklist.src_addr = request->client_addr;
    checklist.my_addr = request->my_addr;

#if 0 && USE_IDENT
    /*
     * this is currently broken because 'request->user_ident' has been
     * moved to conn->rfc931 and we don't have access to the parent
     * ConnStateData here.
     */
    if (request->user_ident[0])
        xstrncpy(checklist.rfc931, request->user_ident, USER_IDENT_SZ);

#endif

    return checklist.fastCheck();
}

/* Return TRUE if it is okay to send an ICP request to this peer.   */
static int
peerWouldBePinged(const peer * p, HttpRequest * request)
{
    if (!peerAllowedToUse(p, request))
        return 0;

    if (p->options.no_query)
        return 0;

    if (p->options.background_ping && (squid_curtime - p->stats.last_query < Config.backgroundPingRate))
        return 0;

    if (p->options.mcast_responder)
        return 0;

    if (p->n_addresses == 0)
        return 0;

    if (p->icp.port == 0)
        return 0;

    /* the case below seems strange, but can happen if the
     * URL host is on the other side of a firewall */
    if (p->type == PEER_SIBLING)
        if (!request->flags.hierarchical)
            return 0;

    /* Ping dead peers every timeout interval */
    if (squid_curtime - p->stats.last_query > Config.Timeout.deadPeer)
        return 1;

    if (!neighborUp(p))
        return 0;

    return 1;
}

/* Return TRUE if it is okay to send an HTTP request to this peer. */
int
peerHTTPOkay(const peer * p, HttpRequest * request)
{
    if (!peerAllowedToUse(p, request))
        return 0;

    if (!neighborUp(p))
        return 0;

    if (p->max_conn)
        if (p->stats.conn_open >= p->max_conn)
            return 0;

    return 1;
}

int
neighborsCount(HttpRequest * request)
{
    peer *p = NULL;
    int count = 0;

    for (p = Config.peers; p; p = p->next)
        if (peerWouldBePinged(p, request))
            count++;

    debugs(15, 3, "neighborsCount: " << count);

    return count;
}

peer *
getFirstUpParent(HttpRequest * request)
{
    peer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (!neighborUp(p))
            continue;

        if (neighborType(p, request) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, request))
            continue;

        break;
    }

    debugs(15, 3, "getFirstUpParent: returning " << (p ? p->host : "NULL"));
    return p;
}

peer *
getRoundRobinParent(HttpRequest * request)
{
    peer *p;
    peer *q = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.roundrobin)
            continue;

        if (neighborType(p, request) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, request))
            continue;

        if (p->weight == 0)
            continue;

        if (q) {
            if (p->weight == q->weight) {
                if (q->rr_count < p->rr_count)
                    continue;
            } else if ( ((double) q->rr_count / q->weight) < ((double) p->rr_count / p->weight)) {
                continue;
            }
        }

        q = p;
    }

    if (q)
        q->rr_count++;

    debugs(15, 3, HERE << "returning " << (q ? q->host : "NULL"));

    return q;
}

peer *
getWeightedRoundRobinParent(HttpRequest * request)
{
    peer *p;
    peer *q = NULL;
    int weighted_rtt;

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.weighted_roundrobin)
            continue;

        if (neighborType(p, request) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, request))
            continue;

        if (q && q->rr_count < p->rr_count)
            continue;

        q = p;
    }

    if (q && q->rr_count > 1000000)
        for (p = Config.peers; p; p = p->next) {
            if (!p->options.weighted_roundrobin)
                continue;

            if (neighborType(p, request) != PEER_PARENT)
                continue;

            p->rr_count = 0;
        }

    if (q) {
        weighted_rtt = (q->stats.rtt - q->basetime) / q->weight;

        if (weighted_rtt < 1)
            weighted_rtt = 1;

        q->rr_count += weighted_rtt;

        debugs(15, 3, "getWeightedRoundRobinParent: weighted_rtt " << weighted_rtt);
    }

    debugs(15, 3, "getWeightedRoundRobinParent: returning " << (q ? q->host : "NULL"));
    return q;
}

/**
 * This gets called every 5 minutes to clear the round-robin counter.
 * The exact timing is an arbitrary default, set on estimate timing of a
 * large number of requests in a high-performance environment during the
 * period. The larger the number of requests between cycled resets the
 * more balanced the operations.
 *
 \param data	unused.
 \todo Make the reset timing a selectable parameter in squid.conf
 */
static void
peerClearRRLoop(void *data)
{
    peerClearRR();
    eventAdd("peerClearRR", peerClearRRLoop, data, 5 * 60.0, 0);
}

/**
 * This gets called on startup and restart to kick off the peer round-robin
 * maintenance event. It ensures that no matter how many times its called
 * no more than one event is scheduled.
 */
void
peerClearRRStart(void)
{
    static int event_added = 0;
    if (!event_added) {
        peerClearRRLoop(NULL);
    }
}

/**
 * Called whenever the round-robin counters need to be reset to a sane state.
 * So far those times are:
 *  - On startup and reconfigure - to set the counters to sane initial settings.
 *  -  When a peer has revived from dead, to prevent the revived peer being
 *     flooded with requests which it has 'missed' during the down period.
 */
void
peerClearRR()
{
    peer *p = NULL;
    for (p = Config.peers; p; p = p->next) {
        p->rr_count = 0;
    }
}

/**
 * Perform all actions when a peer is detected revived.
 */
void
peerAlive(peer *p)
{
    if (p->stats.logged_state == PEER_DEAD && p->tcp_up) {
        debugs(15, 1, "Detected REVIVED " << neighborTypeStr(p) << ": " << p->name);
        p->stats.logged_state = PEER_ALIVE;
        peerClearRR();
    }

    p->stats.last_reply = squid_curtime;
    p->stats.probe_start = 0;
}

peer *
getDefaultParent(HttpRequest * request)
{
    peer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (neighborType(p, request) != PEER_PARENT)
            continue;

        if (!p->options.default_parent)
            continue;

        if (!peerHTTPOkay(p, request))
            continue;

        debugs(15, 3, "getDefaultParent: returning " << p->host);

        return p;
    }

    debugs(15, 3, "getDefaultParent: returning NULL");
    return NULL;
}

/*
 * XXX DW thinks this function is equivalent to/redundant with
 * getFirstUpParent().  peerHTTPOkay() only returns true if the
 * peer is UP anyway, so this function would not return a
 * DOWN parent.
 */
peer *
getAnyParent(HttpRequest * request)
{
    peer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (neighborType(p, request) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, request))
            continue;

        debugs(15, 3, "getAnyParent: returning " << p->host);

        return p;
    }

    debugs(15, 3, "getAnyParent: returning NULL");
    return NULL;
}

peer *
getNextPeer(peer * p)
{
    return p->next;
}

peer *
getFirstPeer(void)
{
    return Config.peers;
}

static void
neighborRemove(peer * target)
{
    peer *p = NULL;
    peer **P = NULL;
    p = Config.peers;
    P = &Config.peers;

    while (p) {
        if (target == p)
            break;

        P = &p->next;

        p = p->next;
    }

    if (p) {
        *P = p->next;
        cbdataFree(p);
        Config.npeers--;
    }

    first_ping = Config.peers;
}

static void
neighborsRegisterWithCacheManager()
{
    CacheManager *manager = CacheManager::GetInstance();
    manager->registerAction("server_list",
                            "Peer Cache Statistics",
                            neighborDumpPeers, 0, 1);

    if (theInIcpConnection >= 0) {
        manager->registerAction("non_peers",
                                "List of Unknown sites sending ICP messages",
                                neighborDumpNonPeers, 0, 1);
    }
}

void
neighbors_init(void)
{
    IpAddress nul;
    struct addrinfo *AI = NULL;
    struct servent *sep = NULL;
    const char *me = getMyHostname();
    peer *thisPeer = NULL;
    peer *next = NULL;
    int fd = theInIcpConnection;

    neighborsRegisterWithCacheManager();

    /* setup addrinfo for use */
    nul.InitAddrInfo(AI);

    if (fd >= 0) {

        if (getsockname(fd, AI->ai_addr, &AI->ai_addrlen) < 0)
            debugs(15, 1, "getsockname(" << fd << "," << AI->ai_addr << "," << &AI->ai_addrlen << ") failed.");

        for (thisPeer = Config.peers; thisPeer; thisPeer = next) {
            http_port_list *s = NULL;
            next = thisPeer->next;

            if (0 != strcmp(thisPeer->host, me))
                continue;

            for (s = Config.Sockaddr.http; s; s = s->next) {
                if (thisPeer->http_port != s->s.GetPort())
                    continue;

                debugs(15, 1, "WARNING: Peer looks like this host");

                debugs(15, 1, "         Ignoring " <<
                       neighborTypeStr(thisPeer) << " " << thisPeer->host <<
                       "/" << thisPeer->http_port << "/" <<
                       thisPeer->icp.port);

                neighborRemove(thisPeer);
            }
        }
    }

    peerRefreshDNS((void *) 1);

    if (ICP_INVALID == echo_hdr.opcode) {
        echo_hdr.opcode = ICP_SECHO;
        echo_hdr.version = ICP_VERSION_CURRENT;
        echo_hdr.length = 0;
        echo_hdr.reqnum = 0;
        echo_hdr.flags = 0;
        echo_hdr.pad = 0;
        nul = *AI;
        nul.GetInAddr( *((struct in_addr*)&echo_hdr.shostid) );
        sep = getservbyname("echo", "udp");
        echo_port = sep ? ntohs((u_short) sep->s_port) : 7;
    }

    first_ping = Config.peers;
    nul.FreeAddrInfo(AI);
}

int
neighborsUdpPing(HttpRequest * request,
                 StoreEntry * entry,
                 IRCB * callback,
                 void *callback_data,
                 int *exprep,
                 int *timeout)
{
    const char *url = entry->url();
    MemObject *mem = entry->mem_obj;
    peer *p = NULL;
    int i;
    int reqnum = 0;
    int flags;
    icp_common_t *query;
    int queries_sent = 0;
    int peers_pinged = 0;
    int parent_timeout = 0, parent_exprep = 0;
    int sibling_timeout = 0, sibling_exprep = 0;
    int mcast_timeout = 0, mcast_exprep = 0;

    if (Config.peers == NULL)
        return 0;

    assert(entry->swap_status == SWAPOUT_NONE);

    mem->start_ping = current_time;

    mem->ping_reply_callback = callback;

    mem->ircb_data = callback_data;

    reqnum = icpSetCacheKey((const cache_key *)entry->key);

    for (i = 0, p = first_ping; i++ < Config.npeers; p = p->next) {
        if (p == NULL)
            p = Config.peers;

        debugs(15, 5, "neighborsUdpPing: Peer " << p->host);

        if (!peerWouldBePinged(p, request))
            continue;		/* next peer */

        peers_pinged++;

        debugs(15, 4, "neighborsUdpPing: pinging peer " << p->host << " for '" << url << "'");

        debugs(15, 3, "neighborsUdpPing: key = '" << entry->getMD5Text() << "'");

        debugs(15, 3, "neighborsUdpPing: reqnum = " << reqnum);

#if USE_HTCP
        if (p->options.htcp && !p->options.htcp_only_clr) {
            if (Config.Port.htcp <= 0) {
                debugs(15, DBG_CRITICAL, "HTCP is disabled! Cannot send HTCP request to peer.");
                continue;
            }

            debugs(15, 3, "neighborsUdpPing: sending HTCP query");
            if (htcpQuery(entry, request, p) <= 0) continue; // unable to send.
        } else
#endif
        {
            if (Config.Port.icp <= 0 || theOutIcpConnection <= 0) {
                debugs(15, DBG_CRITICAL, "ICP is disabled! Cannot send ICP request to peer.");
                continue;
            } else {

                if (p->type == PEER_MULTICAST)
                    mcastSetTtl(theOutIcpConnection, p->mcast.ttl);

                if (p->icp.port == echo_port) {
                    debugs(15, 4, "neighborsUdpPing: Looks like a dumb cache, send DECHO ping");
                    echo_hdr.reqnum = reqnum;
                    query = _icp_common_t::createMessage(ICP_DECHO, 0, url, reqnum, 0);
                    icpUdpSend(theOutIcpConnection,p->in_addr,query,LOG_ICP_QUERY,0);
                } else {
                    flags = 0;

                    if (Config.onoff.query_icmp)
                        if (p->icp.version == ICP_VERSION_2)
                            flags |= ICP_FLAG_SRC_RTT;

                    query = _icp_common_t::createMessage(ICP_QUERY, flags, url, reqnum, 0);

                    icpUdpSend(theOutIcpConnection, p->in_addr, query, LOG_ICP_QUERY, 0);
                }
            }
        }

        queries_sent++;

        p->stats.pings_sent++;

        if (p->type == PEER_MULTICAST) {
            mcast_exprep += p->mcast.n_replies_expected;
            mcast_timeout += (p->stats.rtt * p->mcast.n_replies_expected);
        } else if (neighborUp(p)) {
            /* its alive, expect a reply from it */

            if (neighborType(p, request) == PEER_PARENT) {
                parent_exprep++;
                parent_timeout += p->stats.rtt;
            } else {
                sibling_exprep++;
                sibling_timeout += p->stats.rtt;
            }
        } else {
            /* Neighbor is dead; ping it anyway, but don't expect a reply */
            /* log it once at the threshold */

            if (p->stats.logged_state == PEER_ALIVE) {
                debugs(15, 1, "Detected DEAD " << neighborTypeStr(p) << ": " << p->name);
                p->stats.logged_state = PEER_DEAD;
            }
        }

        p->stats.last_query = squid_curtime;

        /*
         * keep probe_start == 0 for a multicast peer,
         * so neighborUp() never says this peer is dead.
         */

        if ((p->type != PEER_MULTICAST) && (p->stats.probe_start == 0))
            p->stats.probe_start = squid_curtime;
    }

    if ((first_ping = first_ping->next) == NULL)
        first_ping = Config.peers;

    /*
     * How many replies to expect?
     */
    *exprep = parent_exprep + sibling_exprep + mcast_exprep;

    /*
     * If there is a configured timeout, use it
     */
    if (Config.Timeout.icp_query)
        *timeout = Config.Timeout.icp_query;
    else {
        if (*exprep > 0) {
            if (parent_exprep)
                *timeout = 2 * parent_timeout / parent_exprep;
            else if (mcast_exprep)
                *timeout = 2 * mcast_timeout / mcast_exprep;
            else
                *timeout = 2 * sibling_timeout / sibling_exprep;
        } else
            *timeout = 2000;	/* 2 seconds */

        if (Config.Timeout.icp_query_max)
            if (*timeout > Config.Timeout.icp_query_max)
                *timeout = Config.Timeout.icp_query_max;

        if (*timeout < Config.Timeout.icp_query_min)
            *timeout = Config.Timeout.icp_query_min;
    }

    return peers_pinged;
}

/* lookup the digest of a given peer */
lookup_t
peerDigestLookup(peer * p, HttpRequest * request)
{
#if USE_CACHE_DIGESTS
    const cache_key *key = request ? storeKeyPublicByRequest(request) : NULL;
    assert(p);
    assert(request);
    debugs(15, 5, "peerDigestLookup: peer " << p->host);
    /* does the peeer have a valid digest? */

    if (!p->digest) {
        debugs(15, 5, "peerDigestLookup: gone!");
        return LOOKUP_NONE;
    } else if (!peerHTTPOkay(p, request)) {
        debugs(15, 5, "peerDigestLookup: !peerHTTPOkay");
        return LOOKUP_NONE;
    } else if (!p->digest->flags.needed) {
        debugs(15, 5, "peerDigestLookup: note need");
        peerDigestNeeded(p->digest);
        return LOOKUP_NONE;
    } else if (!p->digest->flags.usable) {
        debugs(15, 5, "peerDigestLookup: !ready && " << (p->digest->flags.requested ? "" : "!") << "requested");
        return LOOKUP_NONE;
    }

    debugs(15, 5, "peerDigestLookup: OK to lookup peer " << p->host);
    assert(p->digest->cd);
    /* does digest predict a hit? */

    if (!cacheDigestTest(p->digest->cd, key))
        return LOOKUP_MISS;

    debugs(15, 5, "peerDigestLookup: peer " << p->host << " says HIT!");

    return LOOKUP_HIT;

#endif

    return LOOKUP_NONE;
}

/* select best peer based on cache digests */
peer *
neighborsDigestSelect(HttpRequest * request)
{
    peer *best_p = NULL;
#if USE_CACHE_DIGESTS

    int best_rtt = 0;
    int choice_count = 0;
    int ichoice_count = 0;
    peer *p;
    int p_rtt;
    int i;

    if (!request->flags.hierarchical)
        return NULL;

    storeKeyPublicByRequest(request);

    for (i = 0, p = first_ping; i++ < Config.npeers; p = p->next) {
        lookup_t lookup;

        if (!p)
            p = Config.peers;

        if (i == 1)
            first_ping = p;

        lookup = peerDigestLookup(p, request);

        if (lookup == LOOKUP_NONE)
            continue;

        choice_count++;

        if (lookup == LOOKUP_MISS)
            continue;

        p_rtt = netdbHostRtt(p->host);

        debugs(15, 5, "neighborsDigestSelect: peer " << p->host << " rtt: " << p_rtt);

        /* is this peer better than others in terms of rtt ? */
        if (!best_p || (p_rtt && p_rtt < best_rtt)) {
            best_p = p;
            best_rtt = p_rtt;

            if (p_rtt)		/* informative choice (aka educated guess) */
                ichoice_count++;

            debugs(15, 4, "neighborsDigestSelect: peer " << p->host << " leads with rtt " << best_rtt);
        }
    }

    debugs(15, 4, "neighborsDigestSelect: choices: " << choice_count << " (" << ichoice_count << ")");
    peerNoteDigestLookup(request, best_p,
                         best_p ? LOOKUP_HIT : (choice_count ? LOOKUP_MISS : LOOKUP_NONE));
    request->hier.n_choices = choice_count;
    request->hier.n_ichoices = ichoice_count;
#endif

    return best_p;
}

void
peerNoteDigestLookup(HttpRequest * request, peer * p, lookup_t lookup)
{
#if USE_CACHE_DIGESTS

    if (p)
        strncpy(request->hier.cd_host, p->host, sizeof(request->hier.cd_host));
    else
        *request->hier.cd_host = '\0';

    request->hier.cd_lookup = lookup;

    debugs(15, 4, "peerNoteDigestLookup: peer " <<
           (p ? p->host : "<none>") << ", lookup: " <<
           lookup_t_str[lookup]  );

#endif
}

static void
neighborAlive(peer * p, const MemObject * mem, const icp_common_t * header)
{
    peerAlive(p);
    p->stats.pings_acked++;

    if ((icp_opcode) header->opcode <= ICP_END)
        p->icp.counts[header->opcode]++;

    p->icp.version = (int) header->version;
}

static void
neighborUpdateRtt(peer * p, MemObject * mem)
{
    int rtt, rtt_av_factor;

    if (!mem)
        return;

    if (!mem->start_ping.tv_sec)
        return;

    rtt = tvSubMsec(mem->start_ping, current_time);

    if (rtt < 1 || rtt > 10000)
        return;

    rtt_av_factor = RTT_AV_FACTOR;

    if (p->options.weighted_roundrobin)
        rtt_av_factor = RTT_BACKGROUND_AV_FACTOR;

    p->stats.rtt = Math::intAverage(p->stats.rtt, rtt, p->stats.pings_acked, rtt_av_factor);
}

#if USE_HTCP
static void
neighborAliveHtcp(peer * p, const MemObject * mem, const htcpReplyData * htcp)
{
    peerAlive(p);
    p->stats.pings_acked++;
    p->htcp.counts[htcp->hit ? 1 : 0]++;
    p->htcp.version = htcp->version;
}

#endif

static void
neighborCountIgnored(peer * p)
{
    if (p == NULL)
        return;

    p->stats.ignored_replies++;

    NLateReplies++;
}

static peer *non_peers = NULL;

static void
neighborIgnoreNonPeer(const IpAddress &from, icp_opcode opcode)
{
    peer *np;

    for (np = non_peers; np; np = np->next) {
        if (np->in_addr != from)
            continue;

        if (np->in_addr.GetPort() != from.GetPort())
            continue;

        break;
    }

    if (np == NULL) {
        np = (peer *)xcalloc(1, sizeof(peer));
        np->in_addr = from;
        np->icp.port = from.GetPort();
        np->type = PEER_NONE;
        np->host = new char[MAX_IPSTRLEN];
        from.NtoA(np->host,MAX_IPSTRLEN);
        np->next = non_peers;
        non_peers = np;
    }

    np->icp.counts[opcode]++;

    if (isPowTen(++np->stats.ignored_replies))
        debugs(15, 1, "WARNING: Ignored " << np->stats.ignored_replies << " replies from non-peer " << np->host);
}

/* ignoreMulticastReply
 *
 * * We want to ignore replies from multicast peers if the
 * * cache_host_domain rules would normally prevent the peer
 * * from being used
 */
static int
ignoreMulticastReply(peer * p, MemObject * mem)
{
    if (p == NULL)
        return 0;

    if (!p->options.mcast_responder)
        return 0;

    if (peerHTTPOkay(p, mem->request))
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

neighborsUdpAck(const cache_key * key, icp_common_t * header, const IpAddress &from)
{
    peer *p = NULL;
    StoreEntry *entry;
    MemObject *mem = NULL;
    peer_t ntype = PEER_NONE;
    char *opcode_d;
    icp_opcode opcode = (icp_opcode) header->opcode;

    debugs(15, 6, "neighborsUdpAck: opcode " << opcode << " '" << storeKeyText(key) << "'");

    if (NULL != (entry = Store::Root().get(key)))
        mem = entry->mem_obj;

    if ((p = whichPeer(from)))
        neighborAlive(p, mem, header);

    if (opcode > ICP_END)
        return;

    opcode_d = icp_opcode_str[opcode];

    if (p)
        neighborUpdateRtt(p, mem);

    /* Does the entry exist? */
    if (NULL == entry) {
        debugs(12, 3, "neighborsUdpAck: Cache key '" << storeKeyText(key) << "' not found");
        neighborCountIgnored(p);
        return;
    }

    /* check if someone is already fetching it */
    if (EBIT_TEST(entry->flags, ENTRY_DISPATCHED)) {
        debugs(15, 3, "neighborsUdpAck: '" << storeKeyText(key) << "' already being fetched.");
        neighborCountIgnored(p);
        return;
    }

    if (mem == NULL) {
        debugs(15, 2, "Ignoring " << opcode_d << " for missing mem_obj: " << storeKeyText(key));
        neighborCountIgnored(p);
        return;
    }

    if (entry->ping_status != PING_WAITING) {
        debugs(15, 2, "neighborsUdpAck: Late " << opcode_d << " for " << storeKeyText(key));
        neighborCountIgnored(p);
        return;
    }

    if (entry->lock_count == 0) {
        debugs(12, 1, "neighborsUdpAck: '" << storeKeyText(key) << "' has no locks");
        neighborCountIgnored(p);
        return;
    }

    debugs(15, 3, "neighborsUdpAck: " << opcode_d << " for '" << storeKeyText(key) << "' from " << (p ? p->host : "source") << " ");

    if (p) {
        ntype = neighborType(p, mem->request);
    }

    if (ignoreMulticastReply(p, mem)) {
        neighborCountIgnored(p);
    } else if (opcode == ICP_MISS) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else {
            mem->ping_reply_callback(p, ntype, PROTO_ICP, header, mem->ircb_data);
        }
    } else if (opcode == ICP_HIT) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else {
            header->opcode = ICP_HIT;
            mem->ping_reply_callback(p, ntype, PROTO_ICP, header, mem->ircb_data);
        }
    } else if (opcode == ICP_DECHO) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else if (ntype == PEER_SIBLING) {
            debug_trap("neighborsUdpAck: Found non-ICP cache as SIBLING\n");
            debug_trap("neighborsUdpAck: non-ICP neighbors must be a PARENT\n");
        } else {
            mem->ping_reply_callback(p, ntype, PROTO_ICP, header, mem->ircb_data);
        }
    } else if (opcode == ICP_SECHO) {
        if (p) {
            debugs(15, 1, "Ignoring SECHO from neighbor " << p->host);
            neighborCountIgnored(p);
        } else {
            debugs(15, 1, "Unsolicited SECHO from " << from);
        }
    } else if (opcode == ICP_DENIED) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else if (p->stats.pings_acked > 100) {
            if (100 * p->icp.counts[ICP_DENIED] / p->stats.pings_acked > 95) {
                debugs(15, 0, "95%% of replies from '" << p->host << "' are UDP_DENIED");
                debugs(15, 0, "Disabling '" << p->host << "', please check your configuration.");
                neighborRemove(p);
                p = NULL;
            } else {
                neighborCountIgnored(p);
            }
        }
    } else if (opcode == ICP_MISS_NOFETCH) {
        mem->ping_reply_callback(p, ntype, PROTO_ICP, header, mem->ircb_data);
    } else {
        debugs(15, 0, "neighborsUdpAck: Unexpected ICP reply: " << opcode_d);
    }
}

peer *
peerFindByName(const char *name)
{
    peer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (!strcasecmp(name, p->name))
            break;
    }

    return p;
}

peer *
peerFindByNameAndPort(const char *name, unsigned short port)
{
    peer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (strcasecmp(name, p->name))
            continue;

        if (port != p->http_port)
            continue;

        break;
    }

    return p;
}

int
neighborUp(const peer * p)
{
    if (!p->tcp_up) {
        if (!peerProbeConnect((peer *) p)) {
            debugs(15, 8, "neighborUp: DOWN (probed): " << p->host << " (" << p->in_addr << ")");
            return 0;
        }
    }

    /*
     * The peer can not be UP if we don't have any IP addresses
     * for it.
     */
    if (0 == p->n_addresses) {
        debugs(15, 8, "neighborUp: DOWN (no-ip): " << p->host << " (" << p->in_addr << ")");
        return 0;
    }

    if (p->options.no_query) {
        debugs(15, 8, "neighborUp: UP (no-query): " << p->host << " (" << p->in_addr << ")");
        return 1;
    }

    if (p->stats.probe_start != 0 &&
            squid_curtime - p->stats.probe_start > Config.Timeout.deadPeer) {
        debugs(15, 8, "neighborUp: DOWN (dead): " << p->host << " (" << p->in_addr << ")");
        return 0;
    }

    debugs(15, 8, "neighborUp: UP: " << p->host << " (" << p->in_addr << ")");
    return 1;
}

void
peerDestroy(void *data)
{
    peer *p = (peer *)data;

    struct _domain_ping *l = NULL;

    struct _domain_ping *nl = NULL;

    if (p == NULL)
        return;

    for (l = p->peer_domain; l; l = nl) {
        nl = l->next;
        safe_free(l->domain);
        safe_free(l);
    }

    safe_free(p->host);
    safe_free(p->name);
    safe_free(p->domain);
#if USE_CACHE_DIGESTS

    cbdataReferenceDone(p->digest);
#endif
}

void
peerNoteDigestGone(peer * p)
{
#if USE_CACHE_DIGESTS
    cbdataReferenceDone(p->digest);
#endif
}

static void
peerDNSConfigure(const ipcache_addrs *ia, const DnsLookupDetails &, void *data)
{
    peer *p = (peer *)data;

    int j;

    if (p->n_addresses == 0) {
        debugs(15, 1, "Configuring " << neighborTypeStr(p) << " " << p->host << "/" << p->http_port << "/" << p->icp.port);

        if (p->type == PEER_MULTICAST)
            debugs(15, 1, "    Multicast TTL = " << p->mcast.ttl);
    }

    p->n_addresses = 0;

    if (ia == NULL) {
        debugs(0, 0, "WARNING: DNS lookup for '" << p->host << "' failed!");
        return;
    }

    if ((int) ia->count < 1) {
        debugs(0, 0, "WARNING: No IP address found for '" << p->host << "'!");
        return;
    }

    p->tcp_up = p->connect_fail_limit;

    for (j = 0; j < (int) ia->count && j < PEER_MAX_ADDRESSES; j++) {
        p->addresses[j] = ia->in_addrs[j];
        debugs(15, 2, "--> IP address #" << j << ": " << p->addresses[j]);
        p->n_addresses++;
    }

    p->in_addr.SetEmpty();
    p->in_addr = p->addresses[0];
    p->in_addr.SetPort(p->icp.port);

    if (p->type == PEER_MULTICAST)
        peerCountMcastPeersSchedule(p, 10);

#if USE_ICMP
    if (p->type != PEER_MULTICAST)
        if (!p->options.no_netdb_exchange)
            eventAddIsh("netdbExchangeStart", netdbExchangeStart, p, 30.0, 1);
#endif

}

static void
peerRefreshDNS(void *data)
{
    peer *p = NULL;

    if (eventFind(peerRefreshDNS, NULL))
        eventDelete(peerRefreshDNS, NULL);

    if (!data && 0 == stat5minClientRequests()) {
        /* no recent client traffic, wait a bit */
        eventAddIsh("peerRefreshDNS", peerRefreshDNS, NULL, 180.0, 1);
        return;
    }

    for (p = Config.peers; p; p = p->next)
        ipcache_nbgethostbyname(p->host, peerDNSConfigure, p);

    /* Reconfigure the peers every hour */
    eventAddIsh("peerRefreshDNS", peerRefreshDNS, NULL, 3600.0, 1);
}

static void
peerConnectFailedSilent(peer * p)
{
    p->stats.last_connect_failure = squid_curtime;

    if (!p->tcp_up) {
        debugs(15, 2, "TCP connection to " << p->host << "/" << p->http_port <<
               " dead");
        return;
    }

    p->tcp_up--;

    if (!p->tcp_up) {
        debugs(15, 1, "Detected DEAD " << neighborTypeStr(p) << ": " << p->name);
        p->stats.logged_state = PEER_DEAD;
    }
}

void
peerConnectFailed(peer *p)
{
    debugs(15, 1, "TCP connection to " << p->host << "/" << p->http_port << " failed");
    peerConnectFailedSilent(p);
}

void
peerConnectSucceded(peer * p)
{
    if (!p->tcp_up) {
        debugs(15, 2, "TCP connection to " << p->host << "/" << p->http_port << " succeded");
        p->tcp_up = p->connect_fail_limit; // NP: so peerAlive(p) works properly.
        peerAlive(p);
        if (!p->n_addresses)
            ipcache_nbgethostbyname(p->host, peerDNSConfigure, p);
    } else
        p->tcp_up = p->connect_fail_limit;
}

/// called by Comm when test_fd is closed while connect is in progress
static void
peerProbeClosed(int fd, void *data)
{
    peer *p = (peer*)data;
    p->test_fd = -1;
    // it is a failure because we failed to connect
    peerConnectFailedSilent(p);
}

static void
peerProbeConnectTimeout(int fd, void *data)
{
    peer * p = (peer *)data;
    comm_remove_close_handler(fd, &peerProbeClosed, p);
    comm_close(fd);
    p->test_fd = -1;
    peerConnectFailedSilent(p);
}

/*
* peerProbeConnect will be called on dead peers by neighborUp
*/
static int
peerProbeConnect(peer * p)
{
    int fd;
    time_t ctimeout = p->connect_timeout > 0 ? p->connect_timeout
                      : Config.Timeout.peer_connect;
    int ret = squid_curtime - p->stats.last_connect_failure > ctimeout * 10;

    if (p->test_fd != -1)
        return ret;/* probe already running */

    if (squid_curtime - p->stats.last_connect_probe == 0)
        return ret;/* don't probe to often */

    IpAddress temp(getOutgoingAddr(NULL,p));

    // if IPv6 is disabled try to force IPv4-only outgoing.
    if (!Ip::EnableIpv6 && !temp.SetIPv4()) {
        debugs(50, DBG_IMPORTANT, "WARNING: IPv6 is disabled. Failed to use " << temp << " to probe " << p->host);
        return ret;
    }

    // if IPv6 is split-stack, prefer IPv4
    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK) {
        // NP: This is not a great choice of default,
        // but with the current Internet being IPv4-majority has a higher success rate.
        // if setting to IPv4 fails we dont care, that just means to use IPv6 outgoing.
        temp.SetIPv4();
    }

    fd = comm_open(SOCK_STREAM, IPPROTO_TCP, temp, COMM_NONBLOCKING, p->host);

    if (fd < 0)
        return ret;

    comm_add_close_handler(fd, &peerProbeClosed, p);
    commSetTimeout(fd, ctimeout, peerProbeConnectTimeout, p);

    p->test_fd = fd;

    p->stats.last_connect_probe = squid_curtime;

    commConnectStart(p->test_fd,
                     p->host,
                     p->http_port,
                     peerProbeConnectDone,
                     p);

    return ret;
}

static void
peerProbeConnectDone(int fd, const DnsLookupDetails &, comm_err_t status, int xerrno, void *data)
{
    peer *p = (peer*)data;

    if (status == COMM_OK) {
        peerConnectSucceded(p);
    } else {
        peerConnectFailedSilent(p);
    }

    comm_remove_close_handler(fd, &peerProbeClosed, p);
    comm_close(fd);
    p->test_fd = -1;
    return;
}

static void
peerCountMcastPeersSchedule(peer * p, time_t when)
{
    if (p->mcast.flags.count_event_pending)
        return;

    eventAdd("peerCountMcastPeersStart",
             peerCountMcastPeersStart,
             p,
             (double) when, 1);

    p->mcast.flags.count_event_pending = 1;
}

static void
peerCountMcastPeersStart(void *data)
{
    peer *p = (peer *)data;
    ps_state *psstate;
    StoreEntry *fake;
    MemObject *mem;
    icp_common_t *query;
    int reqnum;
    LOCAL_ARRAY(char, url, MAX_URL);
    assert(p->type == PEER_MULTICAST);
    p->mcast.flags.count_event_pending = 0;
    snprintf(url, MAX_URL, "http://");
    p->in_addr.ToURL(url+7, MAX_URL -8 );
    strcat(url, "/");
    fake = storeCreateEntry(url, url, request_flags(), METHOD_GET);
    HttpRequest *req = HttpRequest::CreateFromUrl(url);
    psstate = new ps_state;
    psstate->request = HTTPMSGLOCK(req);
    psstate->entry = fake;
    psstate->callback = NULL;
    psstate->callback_data = cbdataReference(p);
    psstate->ping.start = current_time;
    mem = fake->mem_obj;
    mem->request = HTTPMSGLOCK(psstate->request);
    mem->start_ping = current_time;
    mem->ping_reply_callback = peerCountHandleIcpReply;
    mem->ircb_data = psstate;
    mcastSetTtl(theOutIcpConnection, p->mcast.ttl);
    p->mcast.id = mem->id;
    reqnum = icpSetCacheKey((const cache_key *)fake->key);
    query = _icp_common_t::createMessage(ICP_QUERY, 0, url, reqnum, 0);
    icpUdpSend(theOutIcpConnection,
               p->in_addr,
               query,
               LOG_ICP_QUERY,
               0);
    fake->ping_status = PING_WAITING;
    eventAdd("peerCountMcastPeersDone",
             peerCountMcastPeersDone,
             psstate,
             Config.Timeout.mcast_icp_query / 1000.0, 1);
    p->mcast.flags.counting = 1;
    peerCountMcastPeersSchedule(p, MCAST_COUNT_RATE);
}

static void
peerCountMcastPeersDone(void *data)
{
    ps_state *psstate = (ps_state *)data;
    StoreEntry *fake = psstate->entry;

    if (cbdataReferenceValid(psstate->callback_data)) {
        peer *p = (peer *)psstate->callback_data;
        p->mcast.flags.counting = 0;
        p->mcast.avg_n_members = Math::doubleAverage(p->mcast.avg_n_members, (double) psstate->ping.n_recv, ++p->mcast.n_times_counted, 10);
        debugs(15, 1, "Group " << p->host  << ": " << psstate->ping.n_recv  <<
               " replies, "<< std::setw(4)<< std::setprecision(2) <<
               p->mcast.avg_n_members <<" average, RTT " << p->stats.rtt);
        p->mcast.n_replies_expected = (int) p->mcast.avg_n_members;
    }

    cbdataReferenceDone(psstate->callback_data);

    EBIT_SET(fake->flags, ENTRY_ABORTED);
    HTTPMSGUNLOCK(fake->mem_obj->request);
    fake->releaseRequest();
    fake->unlock();
    HTTPMSGUNLOCK(psstate->request);
    cbdataFree(psstate);
}

static void
peerCountHandleIcpReply(peer * p, peer_t type, protocol_t proto, void *hdrnotused, void *data)
{
    int rtt_av_factor;

    ps_state *psstate = (ps_state *)data;
    StoreEntry *fake = psstate->entry;
    MemObject *mem = fake->mem_obj;
    int rtt = tvSubMsec(mem->start_ping, current_time);
    assert(proto == PROTO_ICP);
    assert(fake);
    assert(mem);
    psstate->ping.n_recv++;
    rtt_av_factor = RTT_AV_FACTOR;

    if (p->options.weighted_roundrobin)
        rtt_av_factor = RTT_BACKGROUND_AV_FACTOR;

    p->stats.rtt = Math::intAverage(p->stats.rtt, rtt, psstate->ping.n_recv, rtt_av_factor);
}

static void
neighborDumpPeers(StoreEntry * sentry)
{
    dump_peers(sentry, Config.peers);
}

static void
neighborDumpNonPeers(StoreEntry * sentry)
{
    dump_peers(sentry, non_peers);
}

void
dump_peer_options(StoreEntry * sentry, peer * p)
{
    if (p->options.proxy_only)
        storeAppendPrintf(sentry, " proxy-only");

    if (p->options.no_query)
        storeAppendPrintf(sentry, " no-query");

    if (p->options.background_ping)
        storeAppendPrintf(sentry, " background-ping");

    if (p->options.no_digest)
        storeAppendPrintf(sentry, " no-digest");

    if (p->options.default_parent)
        storeAppendPrintf(sentry, " default");

    if (p->options.roundrobin)
        storeAppendPrintf(sentry, " round-robin");

    if (p->options.carp)
        storeAppendPrintf(sentry, " carp");

    if (p->options.userhash)
        storeAppendPrintf(sentry, " userhash");

    if (p->options.sourcehash)
        storeAppendPrintf(sentry, " sourcehash");

    if (p->options.weighted_roundrobin)
        storeAppendPrintf(sentry, " weighted-round-robin");

    if (p->options.mcast_responder)
        storeAppendPrintf(sentry, " multicast-responder");

#if PEER_MULTICAST_SIBLINGS
    if (p->options.mcast_siblings)
        storeAppendPrintf(sentry, " multicast-siblings");
#endif

    if (p->weight != 1)
        storeAppendPrintf(sentry, " weight=%d", p->weight);

    if (p->options.closest_only)
        storeAppendPrintf(sentry, " closest-only");

#if USE_HTCP
    if (p->options.htcp)
        storeAppendPrintf(sentry, " htcp");
    if (p->options.htcp_oldsquid)
        storeAppendPrintf(sentry, " htcp-oldsquid");
    if (p->options.htcp_no_clr)
        storeAppendPrintf(sentry, " htcp-no-clr");
    if (p->options.htcp_no_purge_clr)
        storeAppendPrintf(sentry, " htcp-no-purge-clr");
    if (p->options.htcp_only_clr)
        storeAppendPrintf(sentry, " htcp-only-clr");
#endif

    if (p->options.no_netdb_exchange)
        storeAppendPrintf(sentry, " no-netdb-exchange");

#if DELAY_POOLS

    if (p->options.no_delay)
        storeAppendPrintf(sentry, " no-delay");

#endif

    if (p->login)
        storeAppendPrintf(sentry, " login=%s", p->login);

    if (p->mcast.ttl > 0)
        storeAppendPrintf(sentry, " ttl=%d", p->mcast.ttl);

    if (p->connect_timeout > 0)
        storeAppendPrintf(sentry, " connect-timeout=%d", (int) p->connect_timeout);

    if (p->connect_fail_limit != PEER_TCP_MAGIC_COUNT)
        storeAppendPrintf(sentry, " connect-fail-limit=%d", p->connect_fail_limit);

#if USE_CACHE_DIGESTS

    if (p->digest_url)
        storeAppendPrintf(sentry, " digest-url=%s", p->digest_url);

#endif

    if (p->options.allow_miss)
        storeAppendPrintf(sentry, " allow-miss");

    if (p->options.no_tproxy)
        storeAppendPrintf(sentry, " no-tproxy");

    if (p->max_conn > 0)
        storeAppendPrintf(sentry, " max-conn=%d", p->max_conn);

    if (p->options.originserver)
        storeAppendPrintf(sentry, " originserver");

    if (p->domain)
        storeAppendPrintf(sentry, " forceddomain=%s", p->domain);

    if (p->connection_auth == 0)
        storeAppendPrintf(sentry, " connection-auth=off");
    else if (p->connection_auth == 1)
        storeAppendPrintf(sentry, " connection-auth=on");
    else if (p->connection_auth == 2)
        storeAppendPrintf(sentry, " connection-auth=auto");

    storeAppendPrintf(sentry, "\n");
}

static void
dump_peers(StoreEntry * sentry, peer * peers)
{
    peer *e = NULL;
    char ntoabuf[MAX_IPSTRLEN];
    struct _domain_ping *d = NULL;
    icp_opcode op;
    int i;

    if (peers == NULL)
        storeAppendPrintf(sentry, "There are no neighbors installed.\n");

    for (e = peers; e; e = e->next) {
        assert(e->host != NULL);
        storeAppendPrintf(sentry, "\n%-11.11s: %s\n",
                          neighborTypeStr(e),
                          e->name);
        storeAppendPrintf(sentry, "Host       : %s/%d/%d\n",
                          e->host,
                          e->http_port,
                          e->icp.port);
        storeAppendPrintf(sentry, "Flags      :");
        dump_peer_options(sentry, e);

        for (i = 0; i < e->n_addresses; i++) {
            storeAppendPrintf(sentry, "Address[%d] : %s\n", i,
                              e->addresses[i].NtoA(ntoabuf,MAX_IPSTRLEN) );
        }

        storeAppendPrintf(sentry, "Status     : %s\n",
                          neighborUp(e) ? "Up" : "Down");
        storeAppendPrintf(sentry, "FETCHES    : %d\n", e->stats.fetches);
        storeAppendPrintf(sentry, "OPEN CONNS : %d\n", e->stats.conn_open);
        storeAppendPrintf(sentry, "AVG RTT    : %d msec\n", e->stats.rtt);

        if (!e->options.no_query) {
            storeAppendPrintf(sentry, "LAST QUERY : %8d seconds ago\n",
                              (int) (squid_curtime - e->stats.last_query));

            if (e->stats.last_reply > 0)
                storeAppendPrintf(sentry, "LAST REPLY : %8d seconds ago\n",
                                  (int) (squid_curtime - e->stats.last_reply));
            else
                storeAppendPrintf(sentry, "LAST REPLY : none received\n");

            storeAppendPrintf(sentry, "PINGS SENT : %8d\n", e->stats.pings_sent);

            storeAppendPrintf(sentry, "PINGS ACKED: %8d %3d%%\n",
                              e->stats.pings_acked,
                              Math::intPercent(e->stats.pings_acked, e->stats.pings_sent));
        }

        storeAppendPrintf(sentry, "IGNORED    : %8d %3d%%\n", e->stats.ignored_replies, Math::intPercent(e->stats.ignored_replies, e->stats.pings_acked));

        if (!e->options.no_query) {
            storeAppendPrintf(sentry, "Histogram of PINGS ACKED:\n");
#if USE_HTCP

            if (e->options.htcp) {
                storeAppendPrintf(sentry, "\tMisses\t%8d %3d%%\n",
                                  e->htcp.counts[0],
                                  Math::intPercent(e->htcp.counts[0], e->stats.pings_acked));
                storeAppendPrintf(sentry, "\tHits\t%8d %3d%%\n",
                                  e->htcp.counts[1],
                                  Math::intPercent(e->htcp.counts[1], e->stats.pings_acked));
            } else {
#endif

                for (op = ICP_INVALID; op < ICP_END; ++op) {
                    if (e->icp.counts[op] == 0)
                        continue;

                    storeAppendPrintf(sentry, "    %12.12s : %8d %3d%%\n",
                                      icp_opcode_str[op],
                                      e->icp.counts[op],
                                      Math::intPercent(e->icp.counts[op], e->stats.pings_acked));
                }

#if USE_HTCP

            }

#endif

        }

        if (e->stats.last_connect_failure) {
            storeAppendPrintf(sentry, "Last failed connect() at: %s\n",
                              mkhttpdlogtime(&(e->stats.last_connect_failure)));
        }

        if (e->peer_domain != NULL) {
            storeAppendPrintf(sentry, "DOMAIN LIST: ");

            for (d = e->peer_domain; d; d = d->next) {
                storeAppendPrintf(sentry, "%s%s ",
                                  d->do_ping ? null_string : "!", d->domain);
            }

            storeAppendPrintf(sentry, "\n");
        }

        storeAppendPrintf(sentry, "keep-alive ratio: %d%%\n", Math::intPercent(e->stats.n_keepalives_recv, e->stats.n_keepalives_sent));
    }
}

#if USE_HTCP
void
neighborsHtcpReply(const cache_key * key, htcpReplyData * htcp, const IpAddress &from)
{
    StoreEntry *e = Store::Root().get(key);
    MemObject *mem = NULL;
    peer *p;
    peer_t ntype = PEER_NONE;
    debugs(15, 6, "neighborsHtcpReply: " <<
           (htcp->hit ? "HIT" : "MISS") << " " <<
           storeKeyText(key)  );

    if (NULL != e)
        mem = e->mem_obj;

    if ((p = whichPeer(from)))
        neighborAliveHtcp(p, mem, htcp);

    /* Does the entry exist? */
    if (NULL == e) {
        debugs(12, 3, "neighyborsHtcpReply: Cache key '" << storeKeyText(key) << "' not found");
        neighborCountIgnored(p);
        return;
    }

    /* check if someone is already fetching it */
    if (EBIT_TEST(e->flags, ENTRY_DISPATCHED)) {
        debugs(15, 3, "neighborsUdpAck: '" << storeKeyText(key) << "' already being fetched.");
        neighborCountIgnored(p);
        return;
    }

    if (mem == NULL) {
        debugs(15, 2, "Ignoring reply for missing mem_obj: " << storeKeyText(key));
        neighborCountIgnored(p);
        return;
    }

    if (e->ping_status != PING_WAITING) {
        debugs(15, 2, "neighborsUdpAck: Entry " << storeKeyText(key) << " is not PING_WAITING");
        neighborCountIgnored(p);
        return;
    }

    if (e->lock_count == 0) {
        debugs(12, 1, "neighborsUdpAck: '" << storeKeyText(key) << "' has no locks");
        neighborCountIgnored(p);
        return;
    }

    if (p) {
        ntype = neighborType(p, mem->request);
        neighborUpdateRtt(p, mem);
    }

    if (ignoreMulticastReply(p, mem)) {
        neighborCountIgnored(p);
        return;
    }

    debugs(15, 3, "neighborsHtcpReply: e = " << e);
    mem->ping_reply_callback(p, ntype, PROTO_HTCP, htcp, mem->ircb_data);
}

/*
 * Send HTCP CLR messages to all peers configured to receive them.
 */
void
neighborsHtcpClear(StoreEntry * e, const char *uri, HttpRequest * req, const HttpRequestMethod &method, htcp_clr_reason reason)
{
    peer *p;
    char buf[128];

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.htcp) {
            continue;
        }
        if (p->options.htcp_no_clr) {
            continue;
        }
        if (p->options.htcp_no_purge_clr && reason == HTCP_CLR_PURGE) {
            continue;
        }
        debugs(15, 3, "neighborsHtcpClear: sending CLR to " << p->in_addr.ToURL(buf, 128));
        htcpClear(e, uri, req, method, p, reason);
    }
}

#endif
