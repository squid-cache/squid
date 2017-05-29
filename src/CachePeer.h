/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
#include "icp_opcode.h"
#include "ip/Address.h"
#include "security/PeerOptions.h"

//TODO: remove, it is unconditionally defined and always used.
#define PEER_MULTICAST_SIBLINGS 1

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

class NeighborTypeDomainList;
class PconnPool;
class PeerDigest;
class PeerPoolMgr;

class CachePeer
{
    CBDATA_CLASS(CachePeer);

public:
    CachePeer();
    ~CachePeer();

    u_int index;
    char *name;
    char *host;
    peer_t type;

    Ip::Address in_addr;

    struct {
        int pings_sent;
        int pings_acked;
        int fetches;
        int rtt;
        int ignored_replies;
        int n_keepalives_sent;
        int n_keepalives_recv;
        time_t probe_start;
        time_t last_query;
        time_t last_reply;
        time_t last_connect_failure;
        time_t last_connect_probe;
        int logged_state;   /* so we can print dead/revived msgs */
        int conn_open;      /* current opened connections */
    } stats;

    struct {
        int version;
        int counts[ICP_END+1];
        unsigned short port;
    } icp;

#if USE_HTCP
    struct {
        double version;
        int counts[2];
        unsigned short port;
    } htcp;
#endif

    unsigned short http_port;
    NeighborTypeDomainList *typelist;
    acl_access *access;

    struct {
        bool proxy_only;
        bool no_query;
        bool background_ping;
        bool no_digest;
        bool default_parent;
        bool roundrobin;
        bool weighted_roundrobin;
        bool mcast_responder;
        bool closest_only;
#if USE_HTCP
        bool htcp;
        bool htcp_oldsquid;
        bool htcp_no_clr;
        bool htcp_no_purge_clr;
        bool htcp_only_clr;
        bool htcp_forward_clr;
#endif
        bool no_netdb_exchange;
#if USE_DELAY_POOLS
        bool no_delay;
#endif
        bool allow_miss;
        bool carp;
        struct {
            bool set; //If false, whole url is to be used. Overrides others
            bool scheme;
            bool host;
            bool port;
            bool path;
            bool params;
        } carp_key;
#if USE_AUTH
        bool userhash;
#endif
        bool sourcehash;
        bool originserver;
        bool no_tproxy;
#if PEER_MULTICAST_SIBLINGS
        bool mcast_siblings;
#endif
        bool auth_no_keytab;
    } options;

    int weight;
    int basetime;

    struct {
        double avg_n_members;
        int n_times_counted;
        int n_replies_expected;
        int ttl;
        int id;

        struct {
            bool count_event_pending;
            bool counting;
        } flags;
    } mcast;
#if USE_CACHE_DIGESTS

    PeerDigest *digest;
    char *digest_url;
#endif

    int tcp_up;         /* 0 if a connect() fails */
    /// whether to do another TCP probe after current TCP probes
    bool reprobe;

    Ip::Address addresses[10];
    int n_addresses;
    int rr_count;
    CachePeer *next;
    int testing_now;

    struct {
        unsigned int hash;
        double load_multiplier;
        double load_factor; /* normalized weight value */
    } carp;
#if USE_AUTH
    struct {
        unsigned int hash;
        double load_multiplier;
        double load_factor; /* normalized weight value */
    } userhash;
#endif
    struct {
        unsigned int hash;
        double load_multiplier;
        double load_factor; /* normalized weight value */
    } sourcehash;

    char *login;        /* Proxy authorization */
    time_t connect_timeout_raw; ///< connect_timeout; use peerConnectTimeout() instead!
    int connect_fail_limit;
    int max_conn;
    struct {
        PconnPool *pool; ///< idle connection pool for this peer
        CbcPointer<PeerPoolMgr> mgr; ///< pool manager
        int limit; ///< the limit itself
        bool waitingForClose; ///< a conn must close before we open a standby conn
    } standby; ///< optional "cache_peer standby=limit" feature
    char *domain;       /* Forced domain */

    /// security settings for peer connection
    Security::PeerOptions secure;
    Security::ContextPointer sslContext;
    Security::SessionStatePointer sslSession;

    int front_end_https;
    int connection_auth;
};

#endif /* SQUID_CACHEPEER_H_ */

