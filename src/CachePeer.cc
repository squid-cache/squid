/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "base/TextException.h"
#include "CachePeer.h"
#include "defines.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "Parsing.h"
#include "PeerDigest.h"
#include "PeerPoolMgr.h"
#include "rfc1738.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "Store.h"
#include "util.h"

#include <iterator>

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

void
CachePeer::noteFailure(const Http::StatusCode code)
{
    if (Http::Is4xx(code))
        return; // this failure is not our fault

    countFailure();
}

// TODO: Require callers to detail failures instead of using one (and often
// misleading!) "connection failed" phrase for all of them.
/// noteFailure() helper for handling failures attributed to this peer
void
CachePeer::countFailure()
{
    stats.last_connect_failure = squid_curtime;
    if (tcp_up > 0)
        --tcp_up;

    const auto consideredAliveByAdmin = (stats.logged_state == PEER_ALIVE);
    const auto level = consideredAliveByAdmin ? DBG_IMPORTANT : 2;
    debugs(15, level, "ERROR: Connection to " << *this << " failed");

    if (consideredAliveByAdmin) {
        if (!tcp_up) {
            debugs(15, DBG_IMPORTANT, "Detected DEAD " << neighborTypeStr(this) << ": " << name);
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

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.name;
}

/**
 * utility function to prevent getservbyname() being called with a numeric value
 * on Windows at least it returns garage results.
 */
static bool
isUnsignedNumeric(const char *str, size_t len)
{
    if (len < 1) return false;

    for (; len >0 && *str; ++str, --len) {
        if (! isdigit(*str))
            return false;
    }
    return true;
}

/**
 \param proto   'tcp' or 'udp' for protocol
 \returns       Port the named service is supposed to be listening on.
 */
static unsigned short
GetService(const char *proto)
{
    struct servent *port = nullptr;
    /** Parses a port number or service name from the squid.conf */
    char *token = ConfigParser::NextToken();
    if (token == nullptr)
        throw TextException("cache_peer port is missing", Here());

    /** Returns either the service port number from /etc/services */
    if ( !isUnsignedNumeric(token, strlen(token)) )
        port = getservbyname(token, proto);
    if (port != nullptr) {
        return ntohs((unsigned short)port->s_port);
    }
    /** Or a numeric translation of the config text. */
    return xatos(token);
}

/**
 \returns       Port the named TCP service is supposed to be listening on.
 \copydoc GetService(const char *proto)
 */
inline unsigned short
GetTcpService(void)
{
    return GetService("tcp");
}

/**
 \returns       Port the named UDP service is supposed to be listening on.
 \copydoc GetService(const char *proto)
 */
inline unsigned short
GetUdpService(void)
{
    return GetService("udp");
}

static const char *
peer_type_str(const peer_t type)
{
    const char * result;

    switch (type) {

    case PEER_PARENT:
        result = "parent";
        break;

    case PEER_SIBLING:
        result = "sibling";
        break;

    case PEER_MULTICAST:
        result = "multicast";
        break;

    default:
        result = "unknown";
        break;
    }

    return result;
}

peer_t
CachePeers::parseNeighborType(const char *s)
{
    if (!strcmp(s, "parent"))
        return PEER_PARENT;

    if (!strcmp(s, "neighbor"))
        return PEER_SIBLING;

    if (!strcmp(s, "neighbour"))
        return PEER_SIBLING;

    if (!strcmp(s, "sibling"))
        return PEER_SIBLING;

    if (!strcmp(s, "multicast"))
        return PEER_MULTICAST;

    debugs(15, DBG_CRITICAL, "WARNING: Unknown neighbor type: " << s);

    return PEER_SIBLING;
}

void
CachePeers::dump(StoreEntry *entry, const char *name) const
{
    NeighborTypeDomainList *t;
    LOCAL_ARRAY(char, xname, 128);

    for (const auto &peer: cachePeers) {
        const auto p = peer.get();
        storeAppendPrintf(entry, "%s %s %s %d %d name=%s",
                          name,
                          p->host,
                          neighborTypeStr(p),
                          p->http_port,
                          p->icp.port,
                          p->name);
        dump_peer_options(entry, p);

        if (p->access) {
            snprintf(xname, 128, "cache_peer_access %s", p->name);
            dump_acl_access(entry, xname, p->access);
        }

        for (t = p->typelist; t; t = t->next) {
            storeAppendPrintf(entry, "neighbor_type_domain %s %s %s\n",
                              p->host,
                              peer_type_str(t->type),
                              t->domain);
        }
    }
}

void
CachePeers::parse(ConfigParser &)
{
    char *host_str = ConfigParser::NextToken();
    if (!host_str)
        throw TextException("hostname is missing", Here());

    char *token = ConfigParser::NextToken();
    if (!token)
        throw TextException("type is missing", Here());

    const auto p = new CachePeer(host_str);

    p->type = parseNeighborType(token);

    if (p->type == PEER_MULTICAST) {
        p->options.no_digest = true;
        p->options.no_netdb_exchange = true;
    }

    p->http_port = GetTcpService();

    if (!p->http_port) {
        delete p;
        throw TextException("port is missing", Here());
    }

    p->icp.port = GetUdpService();

    while ((token = ConfigParser::NextToken())) {
        if (!strcmp(token, "proxy-only")) {
            p->options.proxy_only = true;
        } else if (!strcmp(token, "no-query")) {
            p->options.no_query = true;
        } else if (!strcmp(token, "background-ping")) {
            p->options.background_ping = true;
        } else if (!strcmp(token, "no-digest")) {
            p->options.no_digest = true;
        } else if (!strcmp(token, "no-tproxy")) {
            p->options.no_tproxy = true;
        } else if (!strcmp(token, "multicast-responder")) {
            p->options.mcast_responder = true;
#if PEER_MULTICAST_SIBLINGS
        } else if (!strcmp(token, "multicast-siblings")) {
            p->options.mcast_siblings = true;
#endif
        } else if (!strncmp(token, "weight=", 7)) {
            p->weight = xatoi(token + 7);
        } else if (!strncmp(token, "basetime=", 9)) {
            p->basetime = xatoi(token + 9);
        } else if (!strcmp(token, "closest-only")) {
            p->options.closest_only = true;
        } else if (!strncmp(token, "ttl=", 4)) {
            p->mcast.ttl = xatoi(token + 4);

            if (p->mcast.ttl < 0)
                p->mcast.ttl = 0;

            if (p->mcast.ttl > 128)
                p->mcast.ttl = 128;
        } else if (!strcmp(token, "default")) {
            p->options.default_parent = true;
        } else if (!strcmp(token, "round-robin")) {
            p->options.roundrobin = true;
        } else if (!strcmp(token, "weighted-round-robin")) {
            p->options.weighted_roundrobin = true;
#if USE_HTCP
        } else if (!strcmp(token, "htcp")) {
            p->options.htcp = true;
        } else if (!strncmp(token, "htcp=", 5) || !strncmp(token, "htcp-", 5)) {
            /* Note: The htcp- form is deprecated, replaced by htcp= */
            p->options.htcp = true;
            char *tmp = xstrdup(token+5);
            char *mode, *nextmode;
            for (mode = nextmode = tmp; mode; mode = nextmode) {
                nextmode = strchr(mode, ',');
                if (nextmode) {
                    *nextmode = '\0';
                    ++nextmode;
                }
                if (!strcmp(mode, "no-clr")) {
                    if (p->options.htcp_only_clr)
                        fatalf("parse_peer: can't set htcp-no-clr and htcp-only-clr simultaneously");
                    p->options.htcp_no_clr = true;
                } else if (!strcmp(mode, "no-purge-clr")) {
                    p->options.htcp_no_purge_clr = true;
                } else if (!strcmp(mode, "only-clr")) {
                    if (p->options.htcp_no_clr)
                        fatalf("parse_peer: can't set htcp no-clr and only-clr simultaneously");
                    p->options.htcp_only_clr = true;
                } else if (!strcmp(mode, "forward-clr")) {
                    p->options.htcp_forward_clr = true;
                } else if (!strcmp(mode, "oldsquid")) {
                    p->options.htcp_oldsquid = true;
                } else {
                    fatalf("invalid HTCP mode '%s'", mode);
                }
            }
            safe_free(tmp);
#endif
        } else if (!strcmp(token, "no-netdb-exchange")) {
            p->options.no_netdb_exchange = true;

        } else if (!strcmp(token, "carp")) {
            if (p->type != PEER_PARENT)
                throw TextException(ToSBuf("non-parent carp cache_peer ", *p), Here());

            p->options.carp = true;
        } else if (!strncmp(token, "carp-key=", 9)) {
            if (p->options.carp != true)
                throw TextException(ToSBuf("carp-key specified on non-carp cache_peer ", *p), Here());
            p->options.carp_key.set = true;
            char *nextkey=token+strlen("carp-key="), *key=nextkey;
            for (; key; key = nextkey) {
                nextkey=strchr(key,',');
                if (nextkey) ++nextkey; // skip the comma, any
                if (0==strncmp(key,"scheme",6)) {
                    p->options.carp_key.scheme = true;
                } else if (0==strncmp(key,"host",4)) {
                    p->options.carp_key.host = true;
                } else if (0==strncmp(key,"port",4)) {
                    p->options.carp_key.port = true;
                } else if (0==strncmp(key,"path",4)) {
                    p->options.carp_key.path = true;
                } else if (0==strncmp(key,"params",6)) {
                    p->options.carp_key.params = true;
                } else {
                    fatalf("invalid carp-key '%s'",key);
                }
            }
        } else if (!strcmp(token, "userhash")) {
#if USE_AUTH
            if (p->type != PEER_PARENT)
                throw TextException(ToSBuf("non-parent userhash cache_peer ", *p), Here());

            p->options.userhash = true;
#else
            throw TextException(ToSBuf("missing authentication support; required for userhash cache_peer ", *p), Here());
#endif
        } else if (!strcmp(token, "sourcehash")) {
            if (p->type != PEER_PARENT)
                throw TextException(ToSBuf("non-parent sourcehash cache_peer ", *p), Here());

            p->options.sourcehash = true;

        } else if (!strcmp(token, "no-delay")) {
#if USE_DELAY_POOLS
            p->options.no_delay = true;
#else
            debugs(0, DBG_CRITICAL, "WARNING: cache_peer option 'no-delay' requires --enable-delay-pools");
#endif
        } else if (!strncmp(token, "login=", 6)) {
            p->login = xstrdup(token + 6);
            rfc1738_unescape(p->login);
        } else if (!strcmp(token, "auth-no-keytab")) {
            p->options.auth_no_keytab = 1;
        } else if (!strncmp(token, "connect-timeout=", 16)) {
            p->connect_timeout_raw = xatoi(token + 16);
        } else if (!strncmp(token, "connect-fail-limit=", 19)) {
            p->connect_fail_limit = xatoi(token + 19);
#if USE_CACHE_DIGESTS
        } else if (!strncmp(token, "digest-url=", 11)) {
            p->digest_url = xstrdup(token + 11);
#endif

        } else if (!strcmp(token, "allow-miss")) {
            p->options.allow_miss = true;
        } else if (!strncmp(token, "max-conn=", 9)) {
            p->max_conn = xatoi(token + 9);
        } else if (!strncmp(token, "standby=", 8)) {
            p->standby.limit = xatoi(token + 8);
        } else if (!strcmp(token, "originserver")) {
            p->options.originserver = true;
        } else if (!strncmp(token, "name=", 5)) {
            p->rename(token + 5);
        } else if (!strncmp(token, "forceddomain=", 13)) {
            safe_free(p->domain);
            if (token[13])
                p->domain = xstrdup(token + 13);

        } else if (strncmp(token, "ssl", 3) == 0) {
#if !USE_OPENSSL
            debugs(0, DBG_CRITICAL, "WARNING: cache_peer option '" << token << "' requires --with-openssl");
#else
            p->secure.parse(token+3);
#endif
        } else if (strncmp(token, "tls-", 4) == 0) {
            p->secure.parse(token+4);
        } else if (strncmp(token, "tls", 3) == 0) {
            p->secure.parse(token+3);
        } else if (strcmp(token, "front-end-https") == 0) {
            p->front_end_https = 1;
        } else if (strcmp(token, "front-end-https=on") == 0) {
            p->front_end_https = 1;
        } else if (strcmp(token, "front-end-https=auto") == 0) {
            p->front_end_https = 2;
        } else if (strcmp(token, "connection-auth=off") == 0) {
            p->connection_auth = 0;
        } else if (strcmp(token, "connection-auth") == 0) {
            p->connection_auth = 1;
        } else if (strcmp(token, "connection-auth=on") == 0) {
            p->connection_auth = 1;
        } else if (strcmp(token, "connection-auth=auto") == 0) {
            p->connection_auth = 2;
        } else if (token[0] == '#') {
            // start of a text comment. stop reading this line.
            break;
        } else {
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Ignoring unknown cache_peer option '" << token << "'");
        }
    }

    if (findCachePeerByName(p->name))
        throw TextException(ToSBuf("cache_peer ", *p, " specified twice"), Here());

    if (p->max_conn > 0 && p->max_conn < p->standby.limit)
        throw TextException(ToSBuf("cache_peer ", *p, " max-conn=", p->max_conn,
                                   " is lower than its standby=", p->standby.limit), Here());

    if (p->weight < 1)
        p->weight = 1;

    if (p->connect_fail_limit < 1)
        p->connect_fail_limit = 10;

#if USE_CACHE_DIGESTS
    if (!p->options.no_digest)
        p->digest = new PeerDigest(p);
#endif

    if (p->secure.encryptTransport)
        p->secure.parseOptions();

    cachePeers.emplace_back(p);

    p->index = cachePeers.size();

    peerClearRRStart();
}

CachePeers::CachePeerList::const_iterator
CachePeers::firstPing() const
{
    auto it = cachePeers.begin();
    std::advance(it, firstPing_);
    return it;
}

void
CachePeers::advanceFirstPing()
{
    assert(firstPing_ <= size());
    if (++firstPing_== size())
        firstPing_ = 0;
}

void
CachePeers::remove(CachePeer *p)
{
    for (auto it = cachePeers.begin(); it != cachePeers.end(); ++it) {
        if (it->get() == p) {
            cachePeers.erase(it);
            break;
        }
    }
    firstPing_ = 0;
}

CachePeers &
cachePeers()
{
    if (!Config.cachePeers) {
        static CachePeers peers;
        return peers;
    }
    return *Config.cachePeers;
}

