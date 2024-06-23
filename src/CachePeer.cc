/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "base/EnumIterator.h"
#include "base/IoManip.h"
#include "CachePeer.h"
#include "defines.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerDigest.h"
#include "PeerPoolMgr.h"
#include "sbuf/Spaces.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "util.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::CachePeer(const char * const hostname):
    name(xstrdup(hostname)),
    host(xstrdup(hostname))
{
    Tolower(host); // but .name preserves original spelling
}

CachePeer::~CachePeer()
{
    xfree(name);
    xfree(host);

    while (NeighborTypeDomainList *l = typelist) {
        typelist = l->next;
        xfree(l->domain);
        xfree(l);
    }

    aclDestroyAccessList(&access);

#if USE_CACHE_DIGESTS
    void *digestTmp = nullptr;
    if (cbdataReferenceValidDone(digest, &digestTmp))
        peerDigestNotePeerGone(static_cast<PeerDigest *>(digestTmp));
    xfree(digest_url);
#endif

    xfree(login);

    delete standby.pool;

    // the mgr job will notice that its owner is gone and stop
    PeerPoolMgr::Checkpoint(standby.mgr, "peer gone");

    xfree(domain);
}

void
CachePeer::noteSuccess()
{
    if (!tcp_up) {
        debugs(15, 2, "connection to " << *this << " succeeded");
        tcp_up = connect_fail_limit; // NP: so peerAlive() works properly.
        peerAlive(this);
    } else {
        tcp_up = connect_fail_limit;
    }
}

// TODO: Require callers to detail failures instead of using one (and often
// misleading!) "connection failed" phrase for all of them.
/// noteFailure() helper for handling failures attributed to this peer
void
CachePeer::noteFailure()
{
    stats.last_connect_failure = squid_curtime;
    if (tcp_up > 0)
        --tcp_up;

    const auto consideredAliveByAdmin = (stats.logged_state == PEER_ALIVE);
    const auto level = consideredAliveByAdmin ? DBG_IMPORTANT : 2;
    debugs(15, level, "ERROR: Connection to " << *this << " failed");

    if (consideredAliveByAdmin) {
        if (!tcp_up) {
            debugs(15, DBG_IMPORTANT, "Detected DEAD " << typeString() << ": " << name);
            stats.logged_state = PEER_DEAD;
        } else {
            debugs(15, 2, "additional failures needed to mark this cache_peer DEAD: " << tcp_up);
        }
    } else {
        assert(!tcp_up);
        debugs(15, 2, "cache_peer " << *this << " is still DEAD");
    }
}

void
CachePeer::rename(const char * const newName)
{
    if (!newName || !*newName)
        throw TextException("cache_peer name=value cannot be empty", Here());

    xfree(name);
    name = xstrdup(newName);
}

time_t
CachePeer::connectTimeout() const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw;
    return Config.Timeout.peer_connect;
}

void
CachePeer::dumpOptions(std::ostream &os) const
{
    if (options.proxy_only)
        os << " proxy-only";

    if (options.no_query)
        os << " no-query";

    if (options.background_ping)
        os << " background-ping";

    if (options.no_digest)
        os << " no-digest";

    if (options.default_parent)
        os << " default";

    if (options.roundrobin)
        os << " round-robin";

    if (options.carp)
        os << " carp";

#if USE_AUTH
    if (options.userhash)
        os << " userhash";
#endif

    if (options.sourcehash)
        os << " sourcehash";

    if (options.weighted_roundrobin)
        os << " weighted-round-robin";

    if (options.mcast_responder)
        os << " multicast-responder";

#if PEER_MULTICAST_SIBLINGS
    if (options.mcast_siblings)
        os << " multicast-siblings";
#endif

    if (weight != 1)
        os << " weight=" << weight;

    if (options.closest_only)
        os << " closest-only";

#if USE_HTCP
    if (options.htcp) {
        os << " htcp";
        std::vector<const char *, PoolingAllocator<const char *>> opts;
        if (options.htcp_oldsquid)
            opts.push_back("oldsquid");
        if (options.htcp_no_clr)
            opts.push_back("no-clr");
        if (options.htcp_no_purge_clr)
            opts.push_back("no-purge-clr");
        if (options.htcp_only_clr)
            opts.push_back("only-clr");
        if (options.htcp_forward_clr)
            opts.push_back("forward-clr");
        os << AsList(opts).prefixedBy("=").delimitedBy(",");
    }
#endif

    if (options.no_netdb_exchange)
        os << " no-netdb-exchange";

#if USE_DELAY_POOLS
    if (options.no_delay)
        os << " no-delay";
#endif

    if (login)
        os << " login=" << login;

    if (mcast.ttl > 0)
        os << " ttl=" << mcast.ttl;

    if (connect_timeout_raw > 0)
        os << " connect-timeout=" << connect_timeout_raw;

    if (connect_fail_limit != PEER_TCP_MAGIC_COUNT)
        os << " connect-fail-limit=" << connect_fail_limit;

#if USE_CACHE_DIGESTS
    if (digest_url)
        os << " digest-url=" << digest_url;
#endif

    if (options.allow_miss)
        os << " allow-miss";

    if (options.no_tproxy)
        os << " no-tproxy";

    if (max_conn > 0)
        os << " max-conn=" << max_conn;

    if (standby.limit > 0)
        os << " standby=" << standby.limit;

    if (options.originserver)
        os << " originserver";

    if (domain)
        os << " forceddomain=" << domain;

    if (connection_auth == 0)
        os << " connection-auth=off";
    else if (connection_auth == 1)
        os << " connection-auth=on";
    // else default connection-auth=auto

    secure.dumpCfg(os, "tls-");
}

void
CachePeer::reportStatistics (std::ostream& yaml) const
{
    yaml <<
         spaces(2) << "- name: \"" << name << "\"\n" <<
         spaces(4) << "type: " << typeString() << '\n' <<
         spaces(4) << "HTTP address: " << host << ':' << http_port << '\n';
    if (icp.port)
        yaml << spaces(4) << "ICP address: " << host << ':' << icp.port << '\n';
    yaml << spaces(4) << "options: ";
    dumpOptions(yaml);
    yaml << '\n';

    std::vector<Ip::Address> addr(addresses, addresses+n_addresses);
    yaml << spaces(4) << "addresses: [ " << AsList(addr).quoted().delimitedBy(", ") << " ]\n";

    yaml <<
         spaces(4) << "status: " << (neighborUp(this) ? "Up" : "Down") << '\n' <<
         spaces(4) << "fetches: " << stats.fetches << '\n' <<
         spaces(4) << "open connections: " << stats.conn_open << '\n' <<
         spaces(4) << "average RTT: " << stats.rtt << " msec\n";

    if (stats.last_query > 0) {
        yaml << spaces(4) << "last query: " <<
             (squid_curtime - stats.last_query) << " seconds ago\n";
    }

    if (stats.last_reply > 0) {
        yaml << spaces(4) << "last reply: " <<
             (squid_curtime - stats.last_reply) << " seconds ago\n";
    }

    yaml << spaces(4) << "pings sent: " << stats.pings_sent << '\n' <<
         spaces(4) << "pings acked: " << stats.pings_acked << " " <<
         Math::intPercent(stats.pings_acked, stats.pings_sent) << "%\n";

    yaml << spaces(4) << "replies ignored: " << stats.ignored_replies << " " <<
         Math::intPercent(stats.ignored_replies, stats.pings_acked) << "%\n";

    auto sectionHeader = AtMostOnce("histogram of pings acked:\n");

#if USE_HTCP
    if (options.htcp) {
        yaml << spaces(4) << sectionHeader;
        yaml << spaces(6) << "HTCP misses: " << htcp.counts[0] << " " <<
             Math::intPercent(htcp.counts[0], stats.pings_acked) << "%\n" <<
             spaces(6) << "HTCP hits: " << htcp.counts[1] << " " <<
             Math::intPercent(htcp.counts[1], stats.pings_acked) << "%\n";
    } else {
#endif
        for (auto op : WholeEnum<icp_opcode>()) {
            if (icp.counts[op] == 0)
                continue;

            yaml << spaces(4) << sectionHeader;
            yaml << spaces(6) <<
                 icp_opcode_str[op] << ": " <<
                 icp.counts[op] << " " <<
                 Math::intPercent(icp.counts[op], stats.pings_acked) << "%\n";
        }
#if USE_HTCP
    }
#endif

    if (stats.last_connect_failure) {
        yaml << spaces(4) << "last failed connection at: " <<
             Time::FormatHttpd(stats.last_connect_failure) << '\n';
    }

    yaml << spaces(4) << "keep-alive ratio: " <<
         Math::intPercent(stats.n_keepalives_recv, stats.n_keepalives_sent) << "%\n";
}

const char *
CachePeer::typeString() const
{
    static const char *typeNames[] {
        "non-peer",
        "sibling",
        "parent",
        "multicast group"
    };
    return typeNames[type];
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

