/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHEPEER_H_
#define SQUID_CACHEPEER_H_

#include "acl/forward.h"
#include "base/CbcPointer.h"
#include "enums.h"
#include "http/StatusCode.h"
#include "icp_opcode.h"
#include "ip/Address.h"
#include "security/PeerOptions.h"

#include <iosfwd>

//TODO: remove, it is unconditionally defined and always used.
#define PEER_MULTICAST_SIBLINGS 1

class NeighborTypeDomainList;
class PconnPool;
class PeerDigest;
class PeerPoolMgr;

class CachePeer
{
    CBDATA_CLASS(CachePeer);

public:
    explicit CachePeer(const char *hostname);
    ~CachePeer();

    /// reacts to a successful establishment of a connection to this cache_peer
    void noteSuccess();

    /// reacts to a failure on a connection to this cache_peer
    /// \param code a received response status code, if any
    void noteFailure(Http::StatusCode code);

    /// (re)configure cache_peer name=value
    void rename(const char *);

    /// \returns the effective connect timeout for the given peer
    time_t connectTimeout() const;

    u_int index = 0;

    /// cache_peer name (if explicitly configured) or hostname (otherwise).
    /// Unique across already configured cache_peers in the current configuration.
    /// Not necessarily unique across discovered non-peers (see mgr:non_peers).
    /// The value may change during CachePeer configuration.
    /// The value affects various peer selection hashes (e.g., carp.hash).
    /// Preserves configured spelling (i.e. does not lower letters case).
    /// Never nil.
    char *name = nullptr;

    /// The lowercase version of the configured cache_peer hostname or
    /// the IP address of a non-peer (see mgr:non_peers).
    /// May not be unique among cache_peers and non-peers.
    /// Never nil.
    char *host = nullptr;

    peer_t type = PEER_NONE;

    Ip::Address in_addr;

    struct {
        int pings_sent = 0;
        int pings_acked = 0;
        int fetches = 0;
        int rtt = 0;
        int ignored_replies = 0;
        int n_keepalives_sent = 0;
        int n_keepalives_recv = 0;
        time_t probe_start = 0;
        time_t last_query = 0;
        time_t last_reply = 0;
        time_t last_connect_failure = 0;
        time_t last_connect_probe = 0;
        int logged_state = PEER_ALIVE;   ///< so we can print dead/revived msgs
        int conn_open = 0;               ///< current opened connections
    } stats;

    struct icp_ {
        icp_() { memset(&counts, 0, sizeof(counts)); }
        int version = ICP_VERSION_CURRENT;
        int counts[ICP_END+1];
        unsigned short port = CACHE_ICP_PORT;
    } icp;

#if USE_HTCP
    struct {
        double version = 0.0;
        int counts[2] = {0, 0};
        unsigned short port = 0;
    } htcp;
#endif

    unsigned short http_port = CACHE_HTTP_PORT;
    NeighborTypeDomainList *typelist = nullptr;
    acl_access *access = nullptr;

    struct {
        bool proxy_only = false;
        bool no_query = false;
        bool background_ping = false;
        bool no_digest = false;
        bool default_parent = false;
        bool roundrobin = false;
        bool weighted_roundrobin = false;
        bool mcast_responder = false;
        bool closest_only = false;
#if USE_HTCP
        bool htcp = false;
        bool htcp_oldsquid = false;
        bool htcp_no_clr = false;
        bool htcp_no_purge_clr = false;
        bool htcp_only_clr = false;
        bool htcp_forward_clr = false;
#endif
        bool no_netdb_exchange = false;
#if USE_DELAY_POOLS
        bool no_delay = false;
#endif
        bool allow_miss = false;
        bool carp = false;
        struct {
            bool set = false; //If false, whole url is to be used. Overrides others
            bool scheme = false;
            bool host = false;
            bool port = false;
            bool path = false;
            bool params = false;
        } carp_key;
#if USE_AUTH
        bool userhash = false;
#endif
        bool sourcehash = false;
        bool originserver = false;
        bool no_tproxy = false;
#if PEER_MULTICAST_SIBLINGS
        bool mcast_siblings = false;
#endif
        bool auth_no_keytab = false;
    } options;

    int weight = 1;
    int basetime = 0;

    struct {
        double avg_n_members = 0.0;
        int n_times_counted = 0;
        int n_replies_expected = 0;
        int ttl = 0;
        int id = 0;

        struct {
            bool count_event_pending = false;
            bool counting = false;
        } flags;
    } mcast;

#if USE_CACHE_DIGESTS
    PeerDigest *digest = nullptr;
    char *digest_url = nullptr;
#endif

    /// The number of failures sufficient to stop selecting this cache_peer. All
    /// cache_peer selection algorithms skip cache_peers with 0 tcp_up values.
    /// The initial 0 value prevents unprobed cache_peers from being selected.
    int tcp_up = 0;

    /// whether to do another TCP probe after current TCP probes
    bool reprobe = false;

    Ip::Address addresses[10];
    int n_addresses = 0;
    int rr_count = 0;
    CachePeer *next = nullptr;
    int testing_now = 0;

    struct {
        unsigned int hash = 0;
        double load_multiplier = 0.0;
        double load_factor = 0.0;     ///< normalized weight value
    } carp;
#if USE_AUTH
    struct {
        unsigned int hash = 0;
        double load_multiplier = 0.0;
        double load_factor = 0.0;     ///< normalized weight value
    } userhash;
#endif
    struct {
        unsigned int hash = 0;
        double load_multiplier = 0.0;
        double load_factor = 0.0;     ///< normalized weight value
    } sourcehash;

    char *login = nullptr;        /* Proxy authorization */
    time_t connect_timeout_raw = 0; ///< connect_timeout; use connectTimeout() instead!
    int connect_fail_limit = 0;
    int max_conn = 0;

    /// optional "cache_peer standby=limit" feature
    struct {
        PconnPool *pool = nullptr;    ///< idle connection pool for this peer
        CbcPointer<PeerPoolMgr> mgr;  ///< pool manager
        int limit = 0;                ///< the limit itself
        bool waitingForClose = false; ///< a conn must close before we open a standby conn
    } standby;

    char *domain = nullptr; ///< Forced domain

    /// security settings for peer connection
    Security::PeerOptions secure;
    Security::ContextPointer sslContext;
    Security::SessionStatePointer sslSession;

    int front_end_https = 0; ///< 0 - off, 1 - on, 2 - auto
    int connection_auth = 2; ///< 0 - off, 1 - on, 2 - auto

private:
    void countFailure();
};

/// reacts to a successful establishment of a connection to an origin server or cache_peer
/// \param peer nil if Squid established a connection to an origin server
inline void
NoteOutgoingConnectionSuccess(CachePeer * const peer)
{
    if (peer)
        peer->noteSuccess();
}

/// reacts to a failure on a connection to an origin server or cache_peer
/// \param peer nil if the connection is to an origin server
/// \param code a received response status code, if any
inline void
NoteOutgoingConnectionFailure(CachePeer * const peer, const Http::StatusCode code)
{
    if (peer)
        peer->noteFailure(code);
}

/// identify the given cache peer in cache.log messages and such
std::ostream &operator <<(std::ostream &, const CachePeer &);

#endif /* SQUID_CACHEPEER_H_ */

