/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 15    Neighbor Routines */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "anyp/PortCfg.h"
#include "base/EnumIterator.h"
#include "CacheDigest.h"
#include "CachePeer.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "event.h"
#include "FwdState.h"
#include "globals.h"
#include "htcp.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "int.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "multicast.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerDigest.h"
#include "PeerPoolMgr.h"
#include "PeerSelectState.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "stat.h"
#include "Store.h"
#include "store_key_md5.h"
#include "tools.h"

/* count mcast group peers every 15 minutes */
#define MCAST_COUNT_RATE 900

bool peerAllowedToUse(const CachePeer *, PeerSelector *);
static int peerWouldBePinged(const CachePeer *, PeerSelector *);
static void neighborRemove(CachePeer *);
static void neighborAlive(CachePeer *, const MemObject *, const icp_common_t *);
#if USE_HTCP
static void neighborAliveHtcp(CachePeer *, const MemObject *, const HtcpReplyData *);
#endif
static void neighborCountIgnored(CachePeer *);
static void peerRefreshDNS(void *);
static IPH peerDNSConfigure;
static void peerProbeConnect(CachePeer *, const bool reprobeIfBusy = false);
static CNCB peerProbeConnectDone;
static void peerCountMcastPeersDone(void *data);
static void peerCountMcastPeersStart(void *data);
static void peerCountMcastPeersSchedule(CachePeer * p, time_t when);
static void peerCountMcastPeersAbort(PeerSelector *);
static void peerCountMcastPeersCreateAndSend(CachePeer *p);
static IRCB peerCountHandleIcpReply;

static void neighborIgnoreNonPeer(const Ip::Address &, icp_opcode);
static OBJH neighborDumpPeers;
static OBJH neighborDumpNonPeers;
static void dump_peers(StoreEntry * sentry, CachePeer * peers);

static unsigned short echo_port;

static int NLateReplies = 0;
static CachePeer *first_ping = NULL;

const char *
neighborTypeStr(const CachePeer * p)
{
    if (p->type == PEER_NONE)
        return "Non-Peer";

    if (p->type == PEER_SIBLING)
        return "Sibling";

    if (p->type == PEER_MULTICAST)
        return "Multicast Group";

    return "Parent";
}

CachePeer *
whichPeer(const Ip::Address &from)
{
    int j;

    CachePeer *p = NULL;
    debugs(15, 3, "whichPeer: from " << from);

    for (p = Config.peers; p; p = p->next) {
        for (j = 0; j < p->n_addresses; ++j) {
            if (from == p->addresses[j] && from.port() == p->icp.port) {
                return p;
            }
        }
    }

    return NULL;
}

peer_t
neighborType(const CachePeer * p, const AnyP::Uri &url)
{

    const NeighborTypeDomainList *d = NULL;

    for (d = p->typelist; d; d = d->next) {
        if (0 == matchDomainName(url.host(), d->domain))
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

/**
 * \return Whether it is appropriate to fetch REQUEST from PEER.
 */
bool
peerAllowedToUse(const CachePeer * p, PeerSelector * ps)
{
    assert(ps);
    HttpRequest *request = ps->request;
    assert(request != NULL);

    if (neighborType(p, request->url) == PEER_SIBLING) {
#if PEER_MULTICAST_SIBLINGS
        if (p->type == PEER_MULTICAST && p->options.mcast_siblings &&
                (request->flags.noCache || request->flags.refresh || request->flags.loopDetected || request->flags.needValidation))
            debugs(15, 2, "peerAllowedToUse(" << p->name << ", " << request->url.authority() << ") : multicast-siblings optimization match");
#endif
        if (request->flags.noCache)
            return false;

        if (request->flags.refresh)
            return false;

        if (request->flags.loopDetected)
            return false;

        if (request->flags.needValidation)
            return false;
    }

    // CONNECT requests are proxy requests. Not to be forwarded to origin servers.
    // Unless the destination port matches, in which case we MAY perform a 'DIRECT' to this CachePeer.
    if (p->options.originserver && request->method == Http::METHOD_CONNECT && request->url.port() != p->http_port)
        return false;

    if (p->access == NULL)
        return true;

    ACLFilledChecklist checklist(p->access, request, NULL);
    checklist.al = ps->al;
    if (ps->al && ps->al->reply) {
        checklist.reply = ps->al->reply.getRaw();
        HTTPMSGLOCK(checklist.reply);
    }
    checklist.syncAle(request, nullptr);
    return checklist.fastCheck().allowed();
}

/* Return TRUE if it is okay to send an ICP request to this CachePeer.   */
static int
peerWouldBePinged(const CachePeer * p, PeerSelector * ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    if (p->icp.port == 0)
        return 0;

    if (p->options.no_query)
        return 0;

    if (p->options.mcast_responder)
        return 0;

    if (p->n_addresses == 0)
        return 0;

    if (p->options.background_ping && (squid_curtime - p->stats.last_query < Config.backgroundPingRate))
        return 0;

    /* the case below seems strange, but can happen if the
     * URL host is on the other side of a firewall */
    if (p->type == PEER_SIBLING)
        if (!request->flags.hierarchical)
            return 0;

    if (!peerAllowedToUse(p, ps))
        return 0;

    /* Ping dead peers every timeout interval */
    if (squid_curtime - p->stats.last_query > Config.Timeout.deadPeer)
        return 1;

    if (!neighborUp(p))
        return 0;

    return 1;
}

bool
peerCanOpenMore(const CachePeer *p)
{
    const int effectiveLimit = p->max_conn <= 0 ? Squid_MaxFD : p->max_conn;
    const int remaining = effectiveLimit - p->stats.conn_open;
    debugs(15, 7, remaining << '=' << effectiveLimit << '-' << p->stats.conn_open);
    return remaining > 0;
}

bool
peerHasConnAvailable(const CachePeer *p)
{
    // Standby connections can be used without opening new connections.
    const int standbys = p->standby.pool ? p->standby.pool->count() : 0;

    // XXX: Some idle pconns can be used without opening new connections.
    // Complication: Idle pconns cannot be reused for some requests.
    const int usableIdles = 0;

    const int available = standbys + usableIdles;
    debugs(15, 7, available << '=' << standbys << '+' << usableIdles);
    return available > 0;
}

void
peerConnClosed(CachePeer *p)
{
    --p->stats.conn_open;
    if (p->standby.waitingForClose && peerCanOpenMore(p)) {
        p->standby.waitingForClose = false;
        PeerPoolMgr::Checkpoint(p->standby.mgr, "conn closed");
    }
}

/* Return TRUE if it is okay to send an HTTP request to this CachePeer. */
int
peerHTTPOkay(const CachePeer * p, PeerSelector * ps)
{
    if (!peerCanOpenMore(p) && !peerHasConnAvailable(p))
        return 0;

    if (!peerAllowedToUse(p, ps))
        return 0;

    if (!neighborUp(p))
        return 0;

    return 1;
}

int
neighborsCount(PeerSelector *ps)
{
    CachePeer *p = NULL;
    int count = 0;

    for (p = Config.peers; p; p = p->next)
        if (peerWouldBePinged(p, ps))
            ++count;

    debugs(15, 3, "neighborsCount: " << count);

    return count;
}

CachePeer *
getFirstUpParent(PeerSelector *ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    CachePeer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (!neighborUp(p))
            continue;

        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, ps))
            continue;

        break;
    }

    debugs(15, 3, "getFirstUpParent: returning " << (p ? p->host : "NULL"));
    return p;
}

CachePeer *
getRoundRobinParent(PeerSelector *ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    CachePeer *p;
    CachePeer *q = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.roundrobin)
            continue;

        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, ps))
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
        ++ q->rr_count;

    debugs(15, 3, HERE << "returning " << (q ? q->host : "NULL"));

    return q;
}

CachePeer *
getWeightedRoundRobinParent(PeerSelector *ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    CachePeer *p;
    CachePeer *q = NULL;
    int weighted_rtt;

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.weighted_roundrobin)
            continue;

        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, ps))
            continue;

        if (q && q->rr_count < p->rr_count)
            continue;

        q = p;
    }

    if (q && q->rr_count > 1000000)
        for (p = Config.peers; p; p = p->next) {
            if (!p->options.weighted_roundrobin)
                continue;

            if (neighborType(p, request->url) != PEER_PARENT)
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
 * \param data    unused
 *
 * TODO: Make the reset timing a selectable parameter in squid.conf
 */
static void
peerClearRRLoop(void *data)
{
    peerClearRR();
    eventAdd("peerClearRR", peerClearRRLoop, data, 5 * 60.0, 0);
}

/**
 * This gets called on startup and restart to kick off the CachePeer round-robin
 * maintenance event. It ensures that no matter how many times its called
 * no more than one event is scheduled.
 */
void
peerClearRRStart(void)
{
    static bool event_added = false;
    if (!event_added) {
        peerClearRRLoop(NULL);
        event_added=true;
    }
}

/**
 * Called whenever the round-robin counters need to be reset to a sane state.
 * So far those times are:
 *  - On startup and reconfigure - to set the counters to sane initial settings.
 *  -  When a CachePeer has revived from dead, to prevent the revived CachePeer being
 *     flooded with requests which it has 'missed' during the down period.
 */
void
peerClearRR()
{
    CachePeer *p = NULL;
    for (p = Config.peers; p; p = p->next) {
        p->rr_count = 1;
    }
}

/**
 * Perform all actions when a CachePeer is detected revived.
 */
void
peerAlive(CachePeer *p)
{
    if (p->stats.logged_state == PEER_DEAD && p->tcp_up) {
        debugs(15, DBG_IMPORTANT, "Detected REVIVED " << neighborTypeStr(p) << ": " << p->name);
        p->stats.logged_state = PEER_ALIVE;
        peerClearRR();
        if (p->standby.mgr.valid())
            PeerPoolMgr::Checkpoint(p->standby.mgr, "revived peer");
    }

    p->stats.last_reply = squid_curtime;
    p->stats.probe_start = 0;
}

CachePeer *
getDefaultParent(PeerSelector *ps)
{
    assert(ps);
    HttpRequest *request = ps->request;

    CachePeer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!p->options.default_parent)
            continue;

        if (!peerHTTPOkay(p, ps))
            continue;

        debugs(15, 3, "getDefaultParent: returning " << p->host);

        return p;
    }

    debugs(15, 3, "getDefaultParent: returning NULL");
    return NULL;
}

CachePeer *
getNextPeer(CachePeer * p)
{
    return p->next;
}

CachePeer *
getFirstPeer(void)
{
    return Config.peers;
}

static void
neighborRemove(CachePeer * target)
{
    CachePeer *p = NULL;
    CachePeer **P = NULL;
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
        p->next = NULL;
        delete p;
        --Config.npeers;
    }

    first_ping = Config.peers;
}

static void
neighborsRegisterWithCacheManager()
{
    Mgr::RegisterAction("server_list",
                        "Peer Cache Statistics",
                        neighborDumpPeers, 0, 1);

    if (Comm::IsConnOpen(icpIncomingConn)) {
        Mgr::RegisterAction("non_peers",
                            "List of Unknown sites sending ICP messages",
                            neighborDumpNonPeers, 0, 1);
    }
}

void
neighbors_init(void)
{
    struct servent *sep = NULL;
    const char *me = getMyHostname();
    CachePeer *thisPeer = NULL;
    CachePeer *next = NULL;

    neighborsRegisterWithCacheManager();

    if (Comm::IsConnOpen(icpIncomingConn)) {

        for (thisPeer = Config.peers; thisPeer; thisPeer = next) {
            next = thisPeer->next;

            if (0 != strcmp(thisPeer->host, me))
                continue;

            for (AnyP::PortCfgPointer s = HttpPortList; s != NULL; s = s->next) {
                if (thisPeer->http_port != s->s.port())
                    continue;

                debugs(15, DBG_IMPORTANT, "WARNING: Peer looks like this host." <<
                       Debug::Extra << "Ignoring " <<
                       neighborTypeStr(thisPeer) << " " << thisPeer->host <<
                       "/" << thisPeer->http_port << "/" <<
                       thisPeer->icp.port);

                neighborRemove(thisPeer);
            }
        }
    }

    peerRefreshDNS((void *) 1);

    sep = getservbyname("echo", "udp");
    echo_port = sep ? ntohs((unsigned short) sep->s_port) : 7;

    first_ping = Config.peers;
}

int
neighborsUdpPing(HttpRequest * request,
                 StoreEntry * entry,
                 IRCB * callback,
                 PeerSelector *ps,
                 int *exprep,
                 int *timeout)
{
    const char *url = entry->url();
    MemObject *mem = entry->mem_obj;
    CachePeer *p = NULL;
    int i;
    int reqnum = 0;
    int flags;
    int peers_pinged = 0;
    int parent_timeout = 0, parent_exprep = 0;
    int sibling_timeout = 0, sibling_exprep = 0;
    int mcast_timeout = 0, mcast_exprep = 0;

    if (Config.peers == NULL)
        return 0;

    assert(!entry->hasDisk());

    mem->start_ping = current_time;

    mem->ping_reply_callback = callback;

    mem->ircb_data = ps;

    reqnum = icpSetCacheKey((const cache_key *)entry->key);

    for (i = 0, p = first_ping; i++ < Config.npeers; p = p->next) {
        if (p == NULL)
            p = Config.peers;

        debugs(15, 5, "neighborsUdpPing: Peer " << p->host);

        if (!peerWouldBePinged(p, ps))
            continue;       /* next CachePeer */

        ++peers_pinged;

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
            if (htcpQuery(entry, request, p) <= 0)
                continue; // unable to send.
        } else
#endif
        {
            if (Config.Port.icp <= 0 || !Comm::IsConnOpen(icpOutgoingConn)) {
                debugs(15, DBG_CRITICAL, "ICP is disabled! Cannot send ICP request to peer.");
                continue;
            } else {

                if (p->type == PEER_MULTICAST)
                    mcastSetTtl(icpOutgoingConn->fd, p->mcast.ttl);

                if (p->icp.port == echo_port) {
                    debugs(15, 4, "neighborsUdpPing: Looks like a dumb cache, send DECHO ping");
                    // TODO: Get ALE from callback_data if possible.
                    icpCreateAndSend(ICP_DECHO, 0, url, reqnum, 0,
                                     icpOutgoingConn->fd, p->in_addr, nullptr);
                } else {
                    flags = 0;

                    if (Config.onoff.query_icmp)
                        if (p->icp.version == ICP_VERSION_2)
                            flags |= ICP_FLAG_SRC_RTT;

                    // TODO: Get ALE from callback_data if possible.
                    icpCreateAndSend(ICP_QUERY, flags, url, reqnum, 0,
                                     icpOutgoingConn->fd, p->in_addr, nullptr);
                }
            }
        }

        ++ p->stats.pings_sent;

        if (p->type == PEER_MULTICAST) {
            mcast_exprep += p->mcast.n_replies_expected;
            mcast_timeout += (p->stats.rtt * p->mcast.n_replies_expected);
        } else if (neighborUp(p)) {
            /* its alive, expect a reply from it */

            if (neighborType(p, request->url) == PEER_PARENT) {
                ++parent_exprep;
                parent_timeout += p->stats.rtt;
            } else {
                ++sibling_exprep;
                sibling_timeout += p->stats.rtt;
            }
        } else {
            /* Neighbor is dead; ping it anyway, but don't expect a reply */
            /* log it once at the threshold */

            if (p->stats.logged_state == PEER_ALIVE) {
                debugs(15, DBG_IMPORTANT, "Detected DEAD " << neighborTypeStr(p) << ": " << p->name);
                p->stats.logged_state = PEER_DEAD;
            }
        }

        p->stats.last_query = squid_curtime;

        /*
         * keep probe_start == 0 for a multicast CachePeer,
         * so neighborUp() never says this CachePeer is dead.
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
            *timeout = 2000;    /* 2 seconds */

        if (Config.Timeout.icp_query_max)
            if (*timeout > Config.Timeout.icp_query_max)
                *timeout = Config.Timeout.icp_query_max;

        if (*timeout < Config.Timeout.icp_query_min)
            *timeout = Config.Timeout.icp_query_min;
    }

    return peers_pinged;
}

/* lookup the digest of a given CachePeer */
lookup_t
peerDigestLookup(CachePeer * p, PeerSelector * ps)
{
#if USE_CACHE_DIGESTS
    assert(ps);
    HttpRequest *request = ps->request;
    const cache_key *key = request ? storeKeyPublicByRequest(request) : NULL;
    assert(p);
    assert(request);
    debugs(15, 5, "peerDigestLookup: peer " << p->host);
    /* does the peeer have a valid digest? */

    if (!p->digest) {
        debugs(15, 5, "peerDigestLookup: gone!");
        return LOOKUP_NONE;
    } else if (!peerHTTPOkay(p, ps)) {
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

    if (!p->digest->cd->contains(key))
        return LOOKUP_MISS;

    debugs(15, 5, "peerDigestLookup: peer " << p->host << " says HIT!");

    return LOOKUP_HIT;

#endif

    return LOOKUP_NONE;
}

/* select best CachePeer based on cache digests */
CachePeer *
neighborsDigestSelect(PeerSelector *ps)
{
    CachePeer *best_p = NULL;
#if USE_CACHE_DIGESTS
    assert(ps);
    HttpRequest *request = ps->request;

    int best_rtt = 0;
    int choice_count = 0;
    int ichoice_count = 0;
    CachePeer *p;
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

        lookup = peerDigestLookup(p, ps);

        if (lookup == LOOKUP_NONE)
            continue;

        ++choice_count;

        if (lookup == LOOKUP_MISS)
            continue;

        p_rtt = netdbHostRtt(p->host);

        debugs(15, 5, "neighborsDigestSelect: peer " << p->host << " rtt: " << p_rtt);

        /* is this CachePeer better than others in terms of rtt ? */
        if (!best_p || (p_rtt && p_rtt < best_rtt)) {
            best_p = p;
            best_rtt = p_rtt;

            if (p_rtt)      /* informative choice (aka educated guess) */
                ++ichoice_count;

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
peerNoteDigestLookup(HttpRequest * request, CachePeer * p, lookup_t lookup)
{
#if USE_CACHE_DIGESTS
    if (p)
        strncpy(request->hier.cd_host, p->host, sizeof(request->hier.cd_host)-1);
    else
        *request->hier.cd_host = '\0';

    request->hier.cd_lookup = lookup;
    debugs(15, 4, "peerNoteDigestLookup: peer " << (p? p->host : "<none>") << ", lookup: " << lookup_t_str[lookup]  );
#endif
}

static void
neighborAlive(CachePeer * p, const MemObject *, const icp_common_t * header)
{
    peerAlive(p);
    ++ p->stats.pings_acked;

    if ((icp_opcode) header->opcode <= ICP_END)
        ++ p->icp.counts[header->opcode];

    p->icp.version = (int) header->version;
}

static void
neighborUpdateRtt(CachePeer * p, MemObject * mem)
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
neighborAliveHtcp(CachePeer * p, const MemObject *, const HtcpReplyData * htcp)
{
    peerAlive(p);
    ++ p->stats.pings_acked;
    ++ p->htcp.counts[htcp->hit ? 1 : 0];
    p->htcp.version = htcp->version;
}

#endif

static void
neighborCountIgnored(CachePeer * p)
{
    if (p == NULL)
        return;

    ++ p->stats.ignored_replies;

    ++NLateReplies;
}

static CachePeer *non_peers = NULL;

static void
neighborIgnoreNonPeer(const Ip::Address &from, icp_opcode opcode)
{
    CachePeer *np;

    for (np = non_peers; np; np = np->next) {
        if (np->in_addr != from)
            continue;

        if (np->in_addr.port() != from.port())
            continue;

        break;
    }

    if (np == NULL) {
        np = new CachePeer;
        np->in_addr = from;
        np->icp.port = from.port();
        np->type = PEER_NONE;
        np->host = new char[MAX_IPSTRLEN];
        from.toStr(np->host,MAX_IPSTRLEN);
        np->next = non_peers;
        non_peers = np;
    }

    ++ np->icp.counts[opcode];

    if (isPowTen(++np->stats.ignored_replies))
        debugs(15, DBG_IMPORTANT, "WARNING: Ignored " << np->stats.ignored_replies << " replies from non-peer " << np->host);
}

/* ignoreMulticastReply
 *
 * * We want to ignore replies from multicast peers if the
 * * cache_host_domain rules would normally prevent the CachePeer
 * * from being used
 */
static int
ignoreMulticastReply(CachePeer * p, PeerSelector * ps)
{
    if (p == NULL)
        return 0;

    if (!p->options.mcast_responder)
        return 0;

    if (peerHTTPOkay(p, ps))
        return 0;

    return 1;
}

/**
 * I should attach these records to the entry.  We take the first
 * hit we get our wait until everyone misses.  The timeout handler
 * call needs to nip this shopping list or call one of the misses.
 *
 * If a hit process is already started, then sobeit
 */
void
neighborsUdpAck(const cache_key * key, icp_common_t * header, const Ip::Address &from)
{
    CachePeer *p = NULL;
    StoreEntry *entry;
    MemObject *mem = NULL;
    peer_t ntype = PEER_NONE;
    icp_opcode opcode = (icp_opcode) header->opcode;

    debugs(15, 6, "neighborsUdpAck: opcode " << opcode << " '" << storeKeyText(key) << "'");

    if ((entry = Store::Root().findCallbackXXX(key)))
        mem = entry->mem_obj;

    if ((p = whichPeer(from)))
        neighborAlive(p, mem, header);

    if (opcode > ICP_END)
        return;

    const char *opcode_d = icp_opcode_str[opcode];

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

    if (!entry->locked()) {
        // TODO: many entries are unlocked; why is this reported at level 1?
        debugs(12, DBG_IMPORTANT, "neighborsUdpAck: '" << storeKeyText(key) << "' has no locks");
        neighborCountIgnored(p);
        return;
    }

    if (!mem->ircb_data) {
        debugs(12, DBG_IMPORTANT, "BUG: missing ICP callback data for " << *entry);
        neighborCountIgnored(p);
        return;
    }

    debugs(15, 3, "neighborsUdpAck: " << opcode_d << " for '" << storeKeyText(key) << "' from " << (p ? p->host : "source") << " ");

    if (p) {
        ntype = neighborType(p, mem->request->url);
    }

    if (ignoreMulticastReply(p, mem->ircb_data)) {
        neighborCountIgnored(p);
    } else if (opcode == ICP_MISS) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else {
            mem->ping_reply_callback(p, ntype, AnyP::PROTO_ICP, header, mem->ircb_data);
        }
    } else if (opcode == ICP_HIT) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else {
            header->opcode = ICP_HIT;
            mem->ping_reply_callback(p, ntype, AnyP::PROTO_ICP, header, mem->ircb_data);
        }
    } else if (opcode == ICP_DECHO) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else if (ntype == PEER_SIBLING) {
            debug_trap("neighborsUdpAck: Found non-ICP cache as SIBLING\n");
            debug_trap("neighborsUdpAck: non-ICP neighbors must be a PARENT\n");
        } else {
            mem->ping_reply_callback(p, ntype, AnyP::PROTO_ICP, header, mem->ircb_data);
        }
    } else if (opcode == ICP_SECHO) {
        if (p) {
            debugs(15, DBG_IMPORTANT, "Ignoring SECHO from neighbor " << p->host);
            neighborCountIgnored(p);
        } else {
            debugs(15, DBG_IMPORTANT, "Unsolicited SECHO from " << from);
        }
    } else if (opcode == ICP_DENIED) {
        if (p == NULL) {
            neighborIgnoreNonPeer(from, opcode);
        } else if (p->stats.pings_acked > 100) {
            if (100 * p->icp.counts[ICP_DENIED] / p->stats.pings_acked > 95) {
                debugs(15, DBG_CRITICAL, "95%% of replies from '" << p->host << "' are UDP_DENIED");
                debugs(15, DBG_CRITICAL, "Disabling '" << p->host << "', please check your configuration.");
                neighborRemove(p);
                p = NULL;
            } else {
                neighborCountIgnored(p);
            }
        }
    } else if (opcode == ICP_MISS_NOFETCH) {
        mem->ping_reply_callback(p, ntype, AnyP::PROTO_ICP, header, mem->ircb_data);
    } else {
        debugs(15, DBG_CRITICAL, "neighborsUdpAck: Unexpected ICP reply: " << opcode_d);
    }
}

CachePeer *
peerFindByName(const char *name)
{
    CachePeer *p = NULL;

    for (p = Config.peers; p; p = p->next) {
        if (!strcasecmp(name, p->name))
            break;
    }

    return p;
}

CachePeer *
peerFindByNameAndPort(const char *name, unsigned short port)
{
    CachePeer *p = NULL;

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
neighborUp(const CachePeer * p)
{
    if (!p->tcp_up) {
        peerProbeConnect(const_cast<CachePeer*>(p));
        return 0;
    }

    /*
     * The CachePeer can not be UP if we don't have any IP addresses
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

/// \returns the effective connect timeout for this peer
time_t
peerConnectTimeout(const CachePeer *peer)
{
    return peer->connect_timeout_raw > 0 ?
           peer->connect_timeout_raw : Config.Timeout.peer_connect;
}

time_t
positiveTimeout(const time_t timeout)
{
    return max(static_cast<time_t>(1), timeout);
}

static void
peerDNSConfigure(const ipcache_addrs *ia, const Dns::LookupDetails &, void *data)
{
    // TODO: connections to no-longer valid IP addresses should be
    // closed when we can detect such IP addresses.

    CachePeer *p = (CachePeer *)data;

    if (p->n_addresses == 0) {
        debugs(15, DBG_IMPORTANT, "Configuring " << neighborTypeStr(p) << " " << p->host << "/" << p->http_port << "/" << p->icp.port);

        if (p->type == PEER_MULTICAST)
            debugs(15, DBG_IMPORTANT, "    Multicast TTL = " << p->mcast.ttl);
    }

    p->n_addresses = 0;

    if (ia == NULL) {
        debugs(0, DBG_CRITICAL, "WARNING: DNS lookup for '" << p->host << "' failed!");
        return;
    }

    if (ia->empty()) {
        debugs(0, DBG_CRITICAL, "WARNING: No IP address found for '" << p->host << "'!");
        return;
    }

    for (const auto &ip: ia->goodAndBad()) { // TODO: Consider using just good().
        if (p->n_addresses < PEER_MAX_ADDRESSES) {
            const auto idx = p->n_addresses++;
            p->addresses[idx] = ip;
            debugs(15, 2, "--> IP address #" << idx << ": " << p->addresses[idx]);
        } else {
            debugs(15, 3, "ignoring remaining " << (ia->size() - p->n_addresses) << " ips");
            break;
        }
    }

    p->in_addr.setEmpty();
    p->in_addr = p->addresses[0];
    p->in_addr.port(p->icp.port);

    peerProbeConnect(p, true); // detect any died or revived peers ASAP

    if (p->type == PEER_MULTICAST)
        peerCountMcastPeersSchedule(p, 10);

#if USE_ICMP
    if (p->type != PEER_MULTICAST && IamWorkerProcess())
        if (!p->options.no_netdb_exchange)
            eventAddIsh("netdbExchangeStart", netdbExchangeStart, p, 30.0, 1);
#endif

    if (p->standby.mgr.valid())
        PeerPoolMgr::Checkpoint(p->standby.mgr, "resolved peer");
}

static void
peerRefreshDNS(void *data)
{
    CachePeer *p = NULL;

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
peerConnectFailedSilent(CachePeer * p)
{
    p->stats.last_connect_failure = squid_curtime;

    if (!p->tcp_up) {
        debugs(15, 2, "TCP connection to " << p->host << "/" << p->http_port <<
               " dead");
        return;
    }

    -- p->tcp_up;

    if (!p->tcp_up) {
        debugs(15, DBG_IMPORTANT, "Detected DEAD " << neighborTypeStr(p) << ": " << p->name);
        p->stats.logged_state = PEER_DEAD;
    }
}

void
peerConnectFailed(CachePeer *p)
{
    debugs(15, DBG_IMPORTANT, "TCP connection to " << p->host << "/" << p->http_port << " failed");
    peerConnectFailedSilent(p);
}

void
peerConnectSucceded(CachePeer * p)
{
    if (!p->tcp_up) {
        debugs(15, 2, "TCP connection to " << p->host << "/" << p->http_port << " succeeded");
        p->tcp_up = p->connect_fail_limit; // NP: so peerAlive(p) works properly.
        peerAlive(p);
        if (!p->n_addresses)
            ipcache_nbgethostbyname(p->host, peerDNSConfigure, p);
    } else
        p->tcp_up = p->connect_fail_limit;
}

/// whether new TCP probes are currently banned
static bool
peerProbeIsBusy(const CachePeer *p)
{
    if (p->testing_now > 0) {
        debugs(15, 8, "yes, probing " << p);
        return true;
    }
    if (squid_curtime - p->stats.last_connect_probe == 0) {
        debugs(15, 8, "yes, just probed " << p);
        return true;
    }
    return false;
}
/*
* peerProbeConnect will be called on dead peers by neighborUp
*/
static void
peerProbeConnect(CachePeer *p, const bool reprobeIfBusy)
{
    if (peerProbeIsBusy(p)) {
        p->reprobe = reprobeIfBusy;
        return;
    }
    p->reprobe = false;

    const time_t ctimeout = peerConnectTimeout(p);
    /* for each IP address of this CachePeer. find one that we can connect to and probe it. */
    for (int i = 0; i < p->n_addresses; ++i) {
        Comm::ConnectionPointer conn = new Comm::Connection;
        conn->remote = p->addresses[i];
        conn->remote.port(p->http_port);
        conn->setPeer(p);
        getOutgoingAddress(NULL, conn);

        ++ p->testing_now;

        AsyncCall::Pointer call = commCbCall(15,3, "peerProbeConnectDone", CommConnectCbPtrFun(peerProbeConnectDone, p));
        Comm::ConnOpener *cs = new Comm::ConnOpener(conn, call, ctimeout);
        cs->setHost(p->host);
        AsyncJob::Start(cs);
    }

    p->stats.last_connect_probe = squid_curtime;
}

static void
peerProbeConnectDone(const Comm::ConnectionPointer &conn, Comm::Flag status, int, void *data)
{
    CachePeer *p = (CachePeer*)data;

    if (status == Comm::OK) {
        peerConnectSucceded(p);
    } else {
        peerConnectFailedSilent(p);
    }

    -- p->testing_now;
    conn->close();
    // TODO: log this traffic.

    if (p->reprobe)
        peerProbeConnect(p);
}

static void
peerCountMcastPeersSchedule(CachePeer * p, time_t when)
{
    if (p->mcast.flags.count_event_pending)
        return;

    eventAdd("peerCountMcastPeersStart",
             peerCountMcastPeersStart,
             p,
             (double) when, 1);

    p->mcast.flags.count_event_pending = true;
}

static void
peerCountMcastPeersStart(void *data)
{
    const auto peer = static_cast<CachePeer*>(data);
    CallContextCreator([peer] {
        peerCountMcastPeersCreateAndSend(peer);
    });
    peerCountMcastPeersSchedule(peer, MCAST_COUNT_RATE);
}

/// initiates an ICP transaction to a multicast peer
static void
peerCountMcastPeersCreateAndSend(CachePeer * const p)
{
    // XXX: Do not create lots of complex fake objects (while abusing their
    // APIs) to pass around a few basic data points like start_ping and ping!
    MemObject *mem;
    int reqnum;
    // TODO: use class AnyP::Uri instead of constructing and re-parsing a string
    LOCAL_ARRAY(char, url, MAX_URL);
    assert(p->type == PEER_MULTICAST);
    p->mcast.flags.count_event_pending = false;
    snprintf(url, MAX_URL, "http://");
    p->in_addr.toUrl(url+7, MAX_URL -8 );
    strcat(url, "/");
    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initPeerMcast);
    auto *req = HttpRequest::FromUrlXXX(url, mx);
    assert(req != nullptr);
    const AccessLogEntry::Pointer ale = new AccessLogEntry;
    ale->request = req;
    CodeContext::Reset(ale);
    StoreEntry *fake = storeCreateEntry(url, url, RequestFlags(), Http::METHOD_GET);
    const auto psstate = new PeerSelector(nullptr);
    psstate->request = req;
    HTTPMSGLOCK(psstate->request);
    psstate->entry = fake;
    psstate->peerCountMcastPeerXXX = cbdataReference(p);
    psstate->ping.start = current_time;
    psstate->al = ale;
    mem = fake->mem_obj;
    mem->request = psstate->request;
    mem->start_ping = current_time;
    mem->ping_reply_callback = peerCountHandleIcpReply;
    mem->ircb_data = psstate;
    mcastSetTtl(icpOutgoingConn->fd, p->mcast.ttl);
    p->mcast.id = mem->id;
    reqnum = icpSetCacheKey((const cache_key *)fake->key);
    icpCreateAndSend(ICP_QUERY, 0, url, reqnum, 0,
                     icpOutgoingConn->fd, p->in_addr, psstate->al);
    fake->ping_status = PING_WAITING; // TODO: refactor to use PeerSelector::startPingWaiting()
    eventAdd("peerCountMcastPeersDone",
             peerCountMcastPeersDone,
             psstate,
             Config.Timeout.mcast_icp_query / 1000.0, 1);
    p->mcast.flags.counting = true;
}

static void
peerCountMcastPeersDone(void *data)
{
    const auto psstate = static_cast<PeerSelector*>(data);
    CallBack(psstate->al, [psstate] {
        peerCountMcastPeersAbort(psstate);
        delete psstate;
    });
}

/// ends counting of multicast ICP replies
/// to the ICP query initiated by peerCountMcastPeersCreateAndSend()
static void
peerCountMcastPeersAbort(PeerSelector * const psstate)
{
    StoreEntry *fake = psstate->entry;

    if (cbdataReferenceValid(psstate->peerCountMcastPeerXXX)) {
        CachePeer *p = (CachePeer *)psstate->peerCountMcastPeerXXX;
        p->mcast.flags.counting = false;
        p->mcast.avg_n_members = Math::doubleAverage(p->mcast.avg_n_members, (double) psstate->ping.n_recv, ++p->mcast.n_times_counted, 10);
        debugs(15, DBG_IMPORTANT, "Group " << p->host  << ": " << psstate->ping.n_recv  <<
               " replies, "<< std::setw(4)<< std::setprecision(2) <<
               p->mcast.avg_n_members <<" average, RTT " << p->stats.rtt);
        p->mcast.n_replies_expected = (int) p->mcast.avg_n_members;
    }

    cbdataReferenceDone(psstate->peerCountMcastPeerXXX);

    fake->abort(); // sets ENTRY_ABORTED and initiates releated cleanup
    fake->mem_obj->request = nullptr;
    fake->unlock("peerCountMcastPeersDone");
}

static void
peerCountHandleIcpReply(CachePeer * p, peer_t, AnyP::ProtocolType proto, void *, void *data)
{
    const auto psstate = static_cast<PeerSelector*>(data);
    StoreEntry *fake = psstate->entry;
    assert(fake);
    MemObject *mem = fake->mem_obj;
    assert(mem);
    int rtt = tvSubMsec(mem->start_ping, current_time);
    assert(proto == AnyP::PROTO_ICP);
    ++ psstate->ping.n_recv;
    int rtt_av_factor = RTT_AV_FACTOR;

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
dump_peer_options(StoreEntry * sentry, CachePeer * p)
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

#if USE_AUTH
    if (p->options.userhash)
        storeAppendPrintf(sentry, " userhash");
#endif

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
    if (p->options.htcp) {
        storeAppendPrintf(sentry, " htcp");
        if (p->options.htcp_oldsquid || p->options.htcp_no_clr || p->options.htcp_no_purge_clr || p->options.htcp_only_clr) {
            bool doneopts = false;
            if (p->options.htcp_oldsquid) {
                storeAppendPrintf(sentry, "oldsquid");
                doneopts = true;
            }
            if (p->options.htcp_no_clr) {
                storeAppendPrintf(sentry, "%sno-clr",(doneopts?",":"="));
                doneopts = true;
            }
            if (p->options.htcp_no_purge_clr) {
                storeAppendPrintf(sentry, "%sno-purge-clr",(doneopts?",":"="));
                doneopts = true;
            }
            if (p->options.htcp_only_clr) {
                storeAppendPrintf(sentry, "%sonly-clr",(doneopts?",":"="));
                //doneopts = true; // uncomment if more opts are added
            }
        }
    }
#endif

    if (p->options.no_netdb_exchange)
        storeAppendPrintf(sentry, " no-netdb-exchange");

#if USE_DELAY_POOLS
    if (p->options.no_delay)
        storeAppendPrintf(sentry, " no-delay");
#endif

    if (p->login)
        storeAppendPrintf(sentry, " login=%s", p->login);

    if (p->mcast.ttl > 0)
        storeAppendPrintf(sentry, " ttl=%d", p->mcast.ttl);

    if (p->connect_timeout_raw > 0)
        storeAppendPrintf(sentry, " connect-timeout=%d", (int)p->connect_timeout_raw);

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
    if (p->standby.limit > 0)
        storeAppendPrintf(sentry, " standby=%d", p->standby.limit);

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

    p->secure.dumpCfg(sentry,"tls-");
    storeAppendPrintf(sentry, "\n");
}

static void
dump_peers(StoreEntry * sentry, CachePeer * peers)
{
    char ntoabuf[MAX_IPSTRLEN];
    int i;

    if (peers == NULL)
        storeAppendPrintf(sentry, "There are no neighbors installed.\n");

    for (CachePeer *e = peers; e; e = e->next) {
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

        for (i = 0; i < e->n_addresses; ++i) {
            storeAppendPrintf(sentry, "Address[%d] : %s\n", i,
                              e->addresses[i].toStr(ntoabuf,MAX_IPSTRLEN) );
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

                for (auto op : WholeEnum<icp_opcode>()) {
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
                              Time::FormatHttpd(e->stats.last_connect_failure));
        }

        storeAppendPrintf(sentry, "keep-alive ratio: %d%%\n", Math::intPercent(e->stats.n_keepalives_recv, e->stats.n_keepalives_sent));
    }
}

#if USE_HTCP
void
neighborsHtcpReply(const cache_key * key, HtcpReplyData * htcp, const Ip::Address &from)
{
    StoreEntry *e = Store::Root().findCallbackXXX(key);
    MemObject *mem = NULL;
    CachePeer *p;
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

    if (!e->locked()) {
        // TODO: many entries are unlocked; why is this reported at level 1?
        debugs(12, DBG_IMPORTANT, "neighborsUdpAck: '" << storeKeyText(key) << "' has no locks");
        neighborCountIgnored(p);
        return;
    }

    if (!mem->ircb_data) {
        debugs(12, DBG_IMPORTANT, "BUG: missing HTCP callback data for " << *e);
        neighborCountIgnored(p);
        return;
    }

    if (p) {
        ntype = neighborType(p, mem->request->url);
        neighborUpdateRtt(p, mem);
    }

    if (ignoreMulticastReply(p, mem->ircb_data)) {
        neighborCountIgnored(p);
        return;
    }

    debugs(15, 3, "neighborsHtcpReply: e = " << e);
    // TODO: Refactor (ping_reply_callback,ircb_data) to add CodeContext.
    mem->ping_reply_callback(p, ntype, AnyP::PROTO_HTCP, htcp, mem->ircb_data);
}

/*
 * Send HTCP CLR messages to all peers configured to receive them.
 */
void
neighborsHtcpClear(StoreEntry * e, HttpRequest * req, const HttpRequestMethod &method, htcp_clr_reason reason)
{
    CachePeer *p;
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
        debugs(15, 3, "neighborsHtcpClear: sending CLR to " << p->in_addr.toUrl(buf, 128));
        htcpClear(e, req, method, p, reason);
    }
}

#endif

