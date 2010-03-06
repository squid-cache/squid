/*
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
#ifndef SQUID_STRUCTS_H
#define SQUID_STRUCTS_H

#include "config.h"
#include "RefCount.h"
#include "cbdata.h"

/* needed for various structures still in structs.h */
#include "dlink.h"
/* needed for the global config */
#include "HttpHeader.h"

#define PEER_MULTICAST_SIBLINGS 1

struct acl_name_list {
    char name[ACL_NAME_SZ];
    acl_name_list *next;
};

struct acl_deny_info_list {
    err_type err_page_id;
    char *err_page_name;
    acl_name_list *acl_list;
    acl_deny_info_list *next;
};


class acl_access;

struct _header_mangler {
    acl_access *access_list;
    char *replacement;
};

class ACLChecklist;

#if SQUID_SNMP

struct _snmp_request_t {
    u_char *buf;
    u_char *outbuf;
    int len;
    int sock;
    long reqid;
    int outlen;

    IpAddress from;

    struct snmp_pdu *PDU;
    ACLChecklist *acl_checklist;
    u_char *community;

    struct snmp_session session;
};

#endif

class ACLList;

struct acl_address {
    acl_address *next;
    ACLList *aclList;

    IpAddress addr;
};

struct acl_tos {
    acl_tos *next;
    ACLList *aclList;
    int tos;
};

struct acl_size_t {
    acl_size_t *next;
    ACLList *aclList;
    int64_t size;
};

struct ushortlist {
    u_short i;
    ushortlist *next;
};

struct relist {
    char *pattern;
    regex_t regex;
    relist *next;
};

#if DELAY_POOLS
#include "DelayConfig.h"
#endif

#if USE_ICMP
#include "icmp/IcmpConfig.h"
#endif

#if USE_ZPH_QOS
#include "ip/QosConfig.h"
#endif

/* forward decl for SquidConfig, see RemovalPolicy.h */

class RemovalPolicySettings;
class external_acl;
class Store;

struct SquidConfig {

    struct {
        /* These should be for the Store::Root instance.
        * this needs pluggable parsing to be done smoothly.
        */
        int highWaterMark;
        int lowWaterMark;
    } Swap;
    size_t memMaxSize;

    struct {
        int64_t min;
        int pct;
        int64_t max;
    } quickAbort;
    int64_t readAheadGap;
    RemovalPolicySettings *replPolicy;
    RemovalPolicySettings *memPolicy;
#if HTTP_VIOLATIONS
    time_t negativeTtl;
#endif
    time_t negativeDnsTtl;
    time_t positiveDnsTtl;
    time_t shutdownLifetime;
    time_t backgroundPingRate;

    struct {
        time_t read;
        time_t lifetime;
        time_t connect;
        time_t forward;
        time_t peer_connect;
        time_t request;
        time_t persistent_request;
        time_t pconn;
        time_t siteSelect;
        time_t deadPeer;
        int icp_query;		/* msec */
        int icp_query_max;	/* msec */
        int icp_query_min;	/* msec */
        int mcast_icp_query;	/* msec */

#if !USE_DNSSERVERS

        time_t idns_retransmit;
        time_t idns_query;
#endif

    } Timeout;
    size_t maxRequestHeaderSize;
    int64_t maxRequestBodySize;
    int64_t maxChunkedRequestBodySize;
    size_t maxReplyHeaderSize;
    acl_size_t *ReplyBodySize;

    struct {
        u_short icp;
#if USE_HTCP

        u_short htcp;
#endif
#if SQUID_SNMP

        u_short snmp;
#endif
    } Port;

    struct {
        http_port_list *http;
#if USE_SSL

        https_port_list *https;
#endif

    } Sockaddr;
#if SQUID_SNMP

    struct {
        char *configFile;
        char *agentInfo;
    } Snmp;
#endif
#if USE_WCCP

    struct {

        IpAddress router;

        IpAddress address;
        int version;
    } Wccp;
#endif
#if USE_WCCPv2

    struct {
        IpAddress_list *router;

        IpAddress address;
        int forwarding_method;
        int return_method;
        int assignment_method;
        int weight;
        int rebuildwait;
        void *info;
    } Wccp2;
#endif

#if USE_ICMP
    IcmpConfig pinger;
#endif

    char *as_whois_server;

    struct {
        char *store;
        char *swap;
#if USE_USERAGENT_LOG

        char *useragent;
#endif
#if USE_REFERER_LOG

        char *referer;
#endif
#if WIP_FWD_LOG

        char *forward;
#endif

        logformat *logformats;

        customlog *accesslogs;

#if ICAP_CLIENT
        customlog *icaplogs;
#endif

        int rotateNumber;
    } Log;
    char *adminEmail;
    char *EmailFrom;
    char *EmailProgram;
    char *effectiveUser;
    char *visible_appname_string;
    char *effectiveGroup;

    struct {
#if USE_DNSSERVERS
        char *dnsserver;
#endif

        wordlist *redirect;
#if USE_UNLINKD

        char *unlinkd;
#endif

        char *diskd;
#if USE_SSL

        char *ssl_password;
#endif

    } Program;
#if USE_DNSSERVERS

    int dnsChildren;
#endif

    int redirectChildren;
    int redirectConcurrency;
    time_t authenticateGCInterval;
    time_t authenticateTTL;
    time_t authenticateIpTTL;

    struct {
#if USE_SQUID_ESI
        char *surrogate_id;
#endif

    } Accel;
    char *appendDomain;
    size_t appendDomainLen;
    char *pidFilename;
    char *netdbFilename;
    char *mimeTablePathname;
    char *etcHostsPath;
    char *visibleHostname;
    char *uniqueHostname;
    wordlist *hostnameAliases;
    char *errHtmlText;

    struct {
        char *host;
        char *file;
        time_t period;
        u_short port;
    } Announce;

    struct {

        IpAddress udp_incoming;

        IpAddress udp_outgoing;
#if SQUID_SNMP

        IpAddress snmp_incoming;

        IpAddress snmp_outgoing;
#endif
        /* FIXME INET6 : this should really be a CIDR value */
        IpAddress client_netmask;
    } Addrs;
    size_t tcpRcvBufsz;
    size_t udpMaxHitObjsz;
    wordlist *hierarchy_stoplist;
    wordlist *mcast_group_list;
    wordlist *dns_nameservers;
    peer *peers;
    int npeers;

    struct {
        int size;
        int low;
        int high;
    } ipcache;

    struct {
        int size;
    } fqdncache;
    int minDirectHops;
    int minDirectRtt;
    cachemgr_passwd *passwd_list;

    struct {
        int objectsPerBucket;
        int64_t avgObjectSize;
        int64_t maxObjectSize;
        int64_t minObjectSize;
        size_t maxInMemObjSize;
    } Store;

    struct {
        int high;
        int low;
        time_t period;
    } Netdb;

    struct {
        int log_udp;
        int res_defnames;
        int anonymizer;
        int client_db;
        int query_icmp;
        int icp_hit_stale;
        int buffered_logs;
        int common_log;
        int log_mime_hdrs;
        int log_fqdn;
        int announce;
        int mem_pools;
        int test_reachability;
        int half_closed_clients;
        int refresh_all_ims;
#if HTTP_VIOLATIONS

        int reload_into_ims;
        int ignore_expect_100;
#endif

        int offline;
        int redir_rewrites_host;
        int prefer_direct;
        int nonhierarchical_direct;
        int strip_query_terms;
        int redirector_bypass;
        int ignore_unknown_nameservers;
        int client_pconns;
        int server_pconns;
        int error_pconns;
#if USE_CACHE_DIGESTS

        int digest_generation;
#endif

        int log_ip_on_direct;
        int ie_refresh;
        int vary_ignore_expire;
        int pipeline_prefetch;

#if USE_SQUID_ESI
        int surrogate_is_remote;
#endif

        int request_entities;
        int detect_broken_server_pconns;
        int balance_on_multiple_ip;
        int relaxed_header_parser;
        int check_hostnames;
        int allow_underscore;
        int via;
        int emailErrData;
        int httpd_suppress_version_string;
        int global_internal_static;
        int dns_require_A;

#if FOLLOW_X_FORWARDED_FOR
        int acl_uses_indirect_client;
        int delay_pool_uses_indirect_client;
        int log_uses_indirect_client;
#endif /* FOLLOW_X_FORWARDED_FOR */

        int WIN32_IpAddrChangeMonitor;
    } onoff;

    int forward_max_tries;

    class ACL *aclList;

    struct {
        acl_access *http;
        acl_access *adapted_http;
        acl_access *icp;
        acl_access *miss;
        acl_access *NeverDirect;
        acl_access *AlwaysDirect;
        acl_access *ASlists;
        acl_access *noCache;
        acl_access *log;
#if SQUID_SNMP

        acl_access *snmp;
#endif
#if HTTP_VIOLATIONS
        acl_access *brokenPosts;
#endif
        acl_access *redirector;
        acl_access *reply;
        acl_address *outgoing_address;
        acl_tos *outgoing_tos;
        acl_tos *clientside_tos;
#if USE_HTCP

        acl_access *htcp;
        acl_access *htcp_clr;
#endif

#if USE_SSL
        acl_access *ssl_bump;
#endif
#if FOLLOW_X_FORWARDED_FOR
        acl_access *followXFF;
#endif /* FOLLOW_X_FORWARDED_FOR */

#if ICAP_CLIENT
        acl_access* icap;
#endif
    } accessList;
    acl_deny_info_list *denyInfoList;
    authConfig authConfiguration;

    struct {
        size_t list_width;
        int list_wrap;
        char *anon_user;
        int passive;
        int epsv_all;
        int epsv;
        int sanitycheck;
        int telnet;
    } Ftp;
    refresh_t *Refresh;

    struct _cacheSwap {
        RefCount<class Store> *swapDirs;
        int n_allocated;
        int n_configured;
    } cacheSwap;

    struct {
        char *directory;
        int use_short_names;
    } icons;
    char *errorDirectory;
#if USE_ERR_LOCALES
    char *errorDefaultLanguage;
    int errorLogMissingLanguages;
#endif
    char *errorStylesheet;

    struct {
        int maxtries;
        int onerror;
    } retry;

    struct {
        size_t limit;
    } MemPools;
#if DELAY_POOLS

    DelayConfig Delay;
#endif

    struct {
        int icp_average;
        int dns_average;
        int http_average;
        int icp_min_poll;
        int dns_min_poll;
        int http_min_poll;
    } comm_incoming;
    int max_open_disk_fds;
    int uri_whitespace;
    int64_t rangeOffsetLimit;
#if MULTICAST_MISS_STREAM

    struct {

        IpAddress addr;
        int ttl;
        unsigned short port;
        char *encode_key;
    } mcast_miss;
#endif

    /* one access list per header type we know of */
    header_mangler request_header_access[HDR_ENUM_END];
    /* one access list per header type we know of */
    header_mangler reply_header_access[HDR_ENUM_END];
    char *coredump_dir;
    char *chroot_dir;
#if USE_CACHE_DIGESTS

    struct {
        int bits_per_entry;
        time_t rebuild_period;
        time_t rewrite_period;
        size_t swapout_chunk_size;
        int rebuild_chunk_percentage;
    } digest;
#endif
#if USE_SSL

    struct {
        int unclean_shutdown;
        char *ssl_engine;
    } SSL;
#endif

    wordlist *ext_methods;

    struct {
        int high_rptm;
        int high_pf;
        size_t high_memory;
    } warnings;
    char *store_dir_select_algorithm;
    int sleep_after_fork;	/* microseconds */
    time_t minimum_expiry_time;	/* seconds */
    external_acl *externalAclHelperList;

#if USE_ZPH_QOS
    QosConfig zph;
#endif

#if USE_SSL

    struct {
        char *cert;
        char *key;
        int version;
        char *options;
        char *cipher;
        char *cafile;
        char *capath;
        char *crlfile;
        char *flags;
        acl_access *cert_error;
        SSL_CTX *sslContext;
    } ssl_client;
#endif

    char *accept_filter;
    int umask;

#if USE_LOADABLE_MODULES
    wordlist *loadable_module_names;
#endif

    int client_ip_max_connections;
};

SQUIDCEXTERN SquidConfig Config;

struct SquidConfig2 {
    struct {
        int enable_purge;
        int mangle_request_headers;
    } onoff;
    uid_t effectiveUserID;
    gid_t effectiveGroupID;
};

SQUIDCEXTERN SquidConfig2 Config2;

struct _close_handler {
    PF *handler;
    void *data;
    close_handler *next;
};

struct _dread_ctrl {
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int end_of_file;
    DRCB *handler;
    void *client_data;
};

struct _dwrite_q {
    off_t file_offset;
    char *buf;
    size_t len;
    size_t buf_offset;
    dwrite_q *next;
    FREE *free_func;
};


/* ETag support is rudimantal;
 * this struct is likely to change
 * Note: "str" points to memory in HttpHeaderEntry (for now)
 *       so ETags should be used as tmp variables only (for now) */

struct _ETag {
    const char *str;		/* quoted-string */
    int weak;			/* true if it is a weak validator */
};

struct _fde_disk {
    DWCB *wrt_handle;
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
    off_t offset;
};

struct _fileMap {
    int max_n_files;
    int n_files_in_map;
    int toggle;
    int nwords;
    unsigned long *file_map;
};

/*
 * Note: HttpBody is used only for messages with a small content that is
 * known a priory (e.g., error messages).
 */

class MemBuf;

struct _HttpBody {
    /* private */
    MemBuf *mb;
};

#include "SquidString.h"
/* http header extention field */

class HttpHdrExtField
{
    String name;		/* field-name  from HTTP/1.1 (no column after name) */
    String value;		/* field-value from HTTP/1.1 */
};

/* http cache control header field */

class HttpHdrCc
{

public:
    int mask;
    int max_age;
    int s_maxage;
    int max_stale;
    String other;
};

/* some fields can hold either time or etag specs (e.g. If-Range) */

struct _TimeOrTag {
    ETag tag;			/* entity tag */
    time_t time;
    int valid;			/* true if struct is usable */
};

/* per field statistics */

class HttpHeaderFieldStat
{

public:
    HttpHeaderFieldStat() : aliveCount(0), seenCount(0), parsCount(0), errCount(0), repCount(0) {}

    int aliveCount;		/* created but not destroyed (count) */
    int seenCount;		/* #fields we've seen */
    int parsCount;		/* #parsing attempts */
    int errCount;		/* #pasring errors */
    int repCount;		/* #repetitons */
};

/* compiled version of HttpHeaderFieldAttrs plus stats */

class HttpHeaderFieldInfo
{

public:
    HttpHeaderFieldInfo() : id (HDR_ACCEPT), type (ftInvalid) {}

    http_hdr_type id;
    String name;
    field_type type;
    HttpHeaderFieldStat stat;
};

struct _http_state_flags {
    unsigned int proxying:1;
    unsigned int keepalive:1;
    unsigned int only_if_cached:1;
    unsigned int headers_parsed:1;
    unsigned int front_end_https:2;
    unsigned int originpeer:1;
    unsigned int keepalive_broken:1;
    unsigned int abuse_detected:1;
    unsigned int request_sent:1;
    unsigned int do_next_read:1;
    unsigned int consume_body_data:1;
    unsigned int chunked:1;
};

struct _ipcache_addrs {
    IpAddress *in_addrs;
    unsigned char *bad_mask;
    unsigned char count;
    unsigned char cur;
    unsigned char badcount;
};

struct _domain_ping {
    char *domain;
    int do_ping;		/* boolean */
    domain_ping *next;
};

struct _domain_type {
    char *domain;
    peer_t type;
    domain_type *next;
};

#if USE_CACHE_DIGESTS

/* statistics for cache digests and other hit "predictors" */

struct _cd_guess_stats {
    /* public, read-only */
    int true_hits;
    int false_hits;
    int true_misses;
    int false_misses;
    int close_hits;		/* tmp, remove it later */
};

#endif

class PeerDigest;

struct peer {
    u_int index;
    char *name;
    char *host;
    peer_t type;

    IpAddress in_addr;

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
        int logged_state;	/* so we can print dead/revived msgs */
        int conn_open;		/* current opened connections */
    } stats;

    struct {
        int version;
        int counts[ICP_END+1];
        u_short port;
    } icp;

#if USE_HTCP
    struct {
        double version;
        int counts[2];
        u_short port;
    } htcp;
#endif

    u_short http_port;
    domain_ping *peer_domain;
    domain_type *typelist;
    acl_access *access;

    struct {
        unsigned int proxy_only:1;
        unsigned int no_query:1;
        unsigned int background_ping:1;
        unsigned int no_digest:1;
        unsigned int default_parent:1;
        unsigned int roundrobin:1;
        unsigned int weighted_roundrobin:1;
        unsigned int mcast_responder:1;
        unsigned int closest_only:1;
#if USE_HTCP
        unsigned int htcp:1;
        unsigned int htcp_oldsquid:1;
        unsigned int htcp_no_clr:1;
        unsigned int htcp_no_purge_clr:1;
        unsigned int htcp_only_clr:1;
        unsigned int htcp_forward_clr:1;
#endif
        unsigned int no_netdb_exchange:1;
#if DELAY_POOLS
        unsigned int no_delay:1;
#endif
        unsigned int allow_miss:1;
        unsigned int carp:1;
        unsigned int userhash:1;
        unsigned int sourcehash:1;
        unsigned int originserver:1;
        unsigned int no_tproxy:1;
#if PEER_MULTICAST_SIBLINGS
        unsigned int mcast_siblings:1;
#endif
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
            unsigned int count_event_pending:1;
            unsigned int counting:1;
        } flags;
    } mcast;
#if USE_CACHE_DIGESTS

    PeerDigest *digest;
    char *digest_url;
#endif

    int tcp_up;			/* 0 if a connect() fails */

    IpAddress addresses[10];
    int n_addresses;
    int rr_count;
    peer *next;
    int test_fd;

    struct {
        unsigned int hash;
        double load_multiplier;
        double load_factor;	/* normalized weight value */
    } carp;

    struct {
        unsigned int hash;
        double load_multiplier;
        double load_factor;	/* normalized weight value */
    } userhash;

    struct {
        unsigned int hash;
        double load_multiplier;
        double load_factor;	/* normalized weight value */
    } sourcehash;

    char *login;		/* Proxy authorization */
    time_t connect_timeout;
    int connect_fail_limit;
    int max_conn;
    char *domain;		/* Forced domain */
#if USE_SSL

    int use_ssl;
    char *sslcert;
    char *sslkey;
    int sslversion;
    char *ssloptions;
    char *sslcipher;
    char *sslcafile;
    char *sslcapath;
    char *sslcrlfile;
    char *sslflags;
    char *ssldomain;
    SSL_CTX *sslContext;
    SSL_SESSION *sslSession;
#endif

    int front_end_https;
    int connection_auth;
};

struct _net_db_name {
    hash_link hash;		/* must be first */
    net_db_name *next;
    netdbEntry *net_db_entry;
};

struct _net_db_peer {
    const char *peername;
    double hops;
    double rtt;
    time_t expires;
};

struct _netdbEntry {
    hash_link hash;		/* must be first */
    char network[MAX_IPSTRLEN];
    int pings_sent;
    int pings_recv;
    double hops;
    double rtt;
    time_t next_ping_time;
    time_t last_use_time;
    int link_count;
    net_db_name *hosts;
    net_db_peer *peers;
    int n_peers_alloc;
    int n_peers;
};


struct _iostats {

    struct {
        int reads;
        int reads_deferred;
        int read_hist[16];
        int writes;
        int write_hist[16];
    }

    Http, Ftp, Gopher;
};


struct request_flags {
    request_flags(): range(0),nocache(0),ims(0),auth(0),cachable(0),hierarchical(0),loopdetect(0),proxy_keepalive(0),proxying(0),refresh(0),redirected(0),need_validation(0),accelerated(0),ignore_cc(0),intercepted(0),spoof_client_ip(0),internal(0),internalclient(0),must_keepalive(0),destinationIPLookedUp_(0) {
#if HTTP_VIOLATIONS
        nocache_hack = 0;
#endif
#if FOLLOW_X_FORWARDED_FOR
        done_follow_x_forwarded_for = 0;
#endif /* FOLLOW_X_FORWARDED_FOR */
    }

    unsigned int range:1;
    unsigned int nocache:1;
    unsigned int ims:1;
    unsigned int auth:1;
    unsigned int cachable:1;
    unsigned int hierarchical:1;
    unsigned int loopdetect:1;
    unsigned int proxy_keepalive:1;
unsigned int proxying:
    1;	/* this should be killed, also in httpstateflags */
    unsigned int refresh:1;
    unsigned int redirected:1;
    unsigned int need_validation:1;
#if HTTP_VIOLATIONS
    unsigned int nocache_hack:1;	/* for changing/ignoring no-cache requests */
#endif
    unsigned int accelerated:1;
    unsigned int ignore_cc:1;
    unsigned int intercepted:1;  /**< transparently intercepted request */
    unsigned int spoof_client_ip:1;  /**< spoof client ip if possible */
    unsigned int internal:1;
    unsigned int internalclient:1;
    unsigned int must_keepalive:1;
    unsigned int connection_auth:1; /** Request wants connection oriented auth */
    unsigned int connection_auth_disabled:1; /** Connection oriented auth can not be supported */
    unsigned int connection_proxy_auth:1; /** Request wants connection oriented auth */
    unsigned int pinned:1;      /* Request sent on a pinned connection */
    unsigned int auth_sent:1;   /* Authentication forwarded */
    unsigned int no_direct:1;	/* Deny direct forwarding unless overriden by always_direct. Used in accelerator mode */

    // When adding new flags, please update cloneAdaptationImmune() as needed.

    bool resetTCP() const;
    void setResetTCP();
    void clearResetTCP();
    void destinationIPLookupCompleted();
    bool destinationIPLookedUp() const;

    // returns a partial copy of the flags that includes only those flags
    // that are safe for a related (e.g., ICAP-adapted) request to inherit
    request_flags cloneAdaptationImmune() const;

#if FOLLOW_X_FORWARDED_FOR
    unsigned int done_follow_x_forwarded_for;
#endif /* FOLLOW_X_FORWARDED_FOR */
private:

    unsigned int reset_tcp:1;
    unsigned int destinationIPLookedUp_:1;
};

struct _link_list {
    void *ptr;

    struct _link_list *next;
};

struct _cachemgr_passwd {
    char *passwd;
    wordlist *actions;
    cachemgr_passwd *next;
};

struct _refresh_t {
    const char *pattern;
    regex_t compiled_pattern;
    time_t min;
    double pct;
    time_t max;
    refresh_t *next;

    struct {
        unsigned int icase:1;
        unsigned int refresh_ims:1;
#if HTTP_VIOLATIONS
        unsigned int override_expire:1;
        unsigned int override_lastmod:1;
        unsigned int reload_into_ims:1;
        unsigned int ignore_reload:1;
        unsigned int ignore_no_cache:1;
        unsigned int ignore_no_store:1;
        unsigned int ignore_must_revalidate:1;
        unsigned int ignore_private:1;
        unsigned int ignore_auth:1;
#endif
    } flags;
};

/*
 * "very generic" histogram;
 * see important comments on hbase_f restrictions in StatHist.c
 */

struct _StatHist {
    int *bins;
    int capacity;
    double min;
    double max;
    double scale;
    hbase_f *val_in;		/* e.g., log() for log-based histogram */
    hbase_f *val_out;		/* e.g., exp() for log based histogram */
};

/*
 * if you add a field to StatCounters,
 * you MUST sync statCountersInitSpecial, statCountersClean, and statCountersCopy
 */

struct _StatCounters {

    struct {
        int clients;
        int requests;
        int hits;
        int mem_hits;
        int disk_hits;
        int errors;
        kb_t kbytes_in;
        kb_t kbytes_out;
        kb_t hit_kbytes_out;
        StatHist miss_svc_time;
        StatHist nm_svc_time;
        StatHist nh_svc_time;
        StatHist hit_svc_time;
        StatHist all_svc_time;
    } client_http;

    struct {

        struct {
            int requests;
            int errors;
            kb_t kbytes_in;
            kb_t kbytes_out;
        } all , http, ftp, other;
    } server;

    struct {
        int pkts_sent;
        int queries_sent;
        int replies_sent;
        int pkts_recv;
        int queries_recv;
        int replies_recv;
        int hits_sent;
        int hits_recv;
        int replies_queued;
        int replies_dropped;
        kb_t kbytes_sent;
        kb_t q_kbytes_sent;
        kb_t r_kbytes_sent;
        kb_t kbytes_recv;
        kb_t q_kbytes_recv;
        kb_t r_kbytes_recv;
        StatHist query_svc_time;
        StatHist reply_svc_time;
        int query_timeouts;
        int times_used;
    } icp;

    struct {
        int pkts_sent;
        int pkts_recv;
    } htcp;

    struct {
        int requests;
    } unlink;

    struct {
        StatHist svc_time;
    } dns;

    struct {
        int times_used;
        kb_t kbytes_sent;
        kb_t kbytes_recv;
        kb_t memory;
        int msgs_sent;
        int msgs_recv;
#if USE_CACHE_DIGESTS

        cd_guess_stats guess;
#endif

        StatHist on_xition_count;
    } cd;

    struct {
        int times_used;
    } netdb;
    int page_faults;
    unsigned long int select_loops;
    int select_fds;
    double select_time;
    double cputime;

    struct timeval timestamp;
    StatHist comm_icp_incoming;
    StatHist comm_dns_incoming;
    StatHist comm_http_incoming;
    StatHist select_fds_hist;

    struct {
        struct {
            int opens;
            int closes;
            int reads;
            int writes;
            int seeks;
            int unlinks;
        } disk;

        struct {
            int accepts;
            int sockets;
            int connects;
            int binds;
            int closes;
            int reads;
            int writes;
            int recvfroms;
            int sendtos;
        } sock;
        int selects;
    } syscalls;
    int aborted_requests;

    struct {
        int files_cleaned;
        int outs;
        int ins;
    } swap;
};

/* per header statistics */

struct _HttpHeaderStat {
    const char *label;
    HttpHeaderMask *owner_mask;

    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
    StatHist scTypeDistr;

    int parsedCount;
    int ccParsedCount;
    int scParsedCount;
    int destroyedCount;
    int busyDestroyedCount;
};


struct _CacheDigest {
    /* public, read-only */
    char *mask;			/* bit mask */
    int mask_size;		/* mask size in bytes */
    int capacity;		/* expected maximum for .count, not a hard limit */
    int bits_per_entry;		/* number of bits allocated for each entry from capacity */
    int count;			/* number of digested entries */
    int del_count;		/* number of deletions performed so far */
};


struct _store_rebuild_data {
    int objcount;		/* # objects successfully reloaded */
    int expcount;		/* # objects expired */
    int scancount;		/* # entries scanned or read from state file */
    int clashcount;		/* # swapfile clashes avoided */
    int dupcount;		/* # duplicates purged */
    int cancelcount;		/* # SWAP_LOG_DEL objects purged */
    int invalid;		/* # bad lines */
    int badflags;		/* # bad e->flags */
    int bad_log_op;
    int zero_object_sz;
};

struct _Logfile {
    int fd;
    char path[MAXPATHLEN];
    char *buf;
    size_t bufsz;
    size_t offset;

    struct {
        unsigned int fatal;
        unsigned int syslog;
    } flags;

    int syslog_priority;
};

class logformat_token;

struct _logformat {
    char *name;
    logformat_token *format;
    logformat *next;
};

struct _customlog {
    char *filename;
    ACLList *aclList;
    logformat *logFormat;
    Logfile *logfile;
    customlog *next;
    customlog_type type;
};

#endif /* SQUID_STRUCTS_H */
