
/*
 * $Id: structs.h,v 1.477 2003/08/04 22:14:42 robertc Exp $
 *
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

#ifndef SQUID_STRUCTS_H
#define SQUID_STRUCTS_H

#include "config.h"

class dlink_node
{

public:
    dlink_node() : data(NULL), prev(NULL), next(NULL){}

    void *data;
    dlink_node *prev;
    dlink_node *next;
};

struct _dlink_list
{
    dlink_node *head;
    dlink_node *tail;
};

struct _acl_name_list
{
    char name[ACL_NAME_SZ];
    acl_name_list *next;
};

struct _acl_proxy_auth_match_cache
{
    dlink_node link;
    int matchrv;
    void *acl_data;
};

struct _acl_deny_info_list
{
    err_type err_page_id;
    char *err_page_name;
    acl_name_list *acl_list;
    acl_deny_info_list *next;
};


class acl_access;

struct _header_mangler
{
    acl_access *access_list;
    char *replacement;
};

struct _body_size
{
    dlink_node node;
    acl_access *access_list;
    size_t maxsize;
};

struct _http_version_t
{
    unsigned int major;
    unsigned int minor;
};

#if SQUID_SNMP

struct _snmp_request_t
{
    u_char *buf;
    u_char *outbuf;
    int len;
    int sock;
    long reqid;
    int outlen;

    struct sockaddr_in from;

    struct snmp_pdu *PDU;
    ACLChecklist *acl_checklist;
    u_char *community;
};

#endif

typedef class ACL acl;


struct _acl_address
{
    acl_address *next;
    acl_list *aclList;

    struct in_addr addr;
};

struct _acl_tos
{
    acl_tos *next;
    acl_list *aclList;
    int tos;
};

struct _acl_size_t
{
    acl_size_t *next;
    acl_list *aclList;
    size_t size;
};

struct _wordlist
{
    char *key;
    wordlist *next;
};

struct _ushortlist
{
    u_short i;
    ushortlist *next;
};

struct _relist
{
    char *pattern;
    regex_t regex;
    relist *next;
};

struct _sockaddr_in_list
{

    struct sockaddr_in s;
    sockaddr_in_list *next;
};

struct _http_port_list
{
    http_port_list *next;

    struct sockaddr_in s;
    char *protocol;            /* protocol name */
    char *name;                /* visible name */
    char *defaultsite;         /* default web site */

unsigned int transparent:
    1; /* transparent proxy */

unsigned int accel:
    1; /* HTTP accelerator */

unsigned int vhost:
    1; /* uses host header */

    int vport;                 /* virtual port support, -1 for dynamic, >0 static*/
};


#if USE_SSL

struct _https_port_list
{
    http_port_list http;	/* must be first */
    char *cert;
    char *key;
    int version;
    char *cipher;
    char *options;
    char *clientca;
    char *cafile;
    char *capath;
    char *dhfile;
    char *sslflags;
    SSL_CTX *sslContext;
};

#endif

#if DELAY_POOLS
#include "DelayConfig.h"
#endif

struct _authConfig
{
    authScheme *schemes;
    int n_allocated;
    int n_configured;
};

struct _RemovalPolicySettings
{
    char *type;
    wordlist *args;
};

class external_acl;

struct _SquidConfig
{

    struct
    {
        size_t maxSize;
        int highWaterMark;
        int lowWaterMark;
    }

    Swap;
    size_t memMaxSize;

    struct
    {
        char *relayHost;
        u_short relayPort;
        peer *_peer;
    }

    Wais;

    struct
    {
        size_t min;
        int pct;
        size_t max;
    }

    quickAbort;
    size_t readAheadGap;
    RemovalPolicySettings *replPolicy;
    RemovalPolicySettings *memPolicy;
    time_t negativeTtl;
    time_t negativeDnsTtl;
    time_t positiveDnsTtl;
    time_t shutdownLifetime;
    time_t backgroundPingRate;

    struct
    {
        time_t read;
        time_t lifetime;
        time_t connect;
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
#if USE_IDENT

        time_t ident;
#endif
#if !USE_DNSSERVERS

        time_t idns_retransmit;
        time_t idns_query;
#endif

    }

    Timeout;
    size_t maxRequestHeaderSize;
    size_t maxRequestBodySize;
    acl_size_t *ReplyBodySize;

    struct
    {
        u_short icp;
#if USE_HTCP

        u_short htcp;
#endif
#if SQUID_SNMP

        u_short snmp;
#endif

    }

    Port;

    struct
    {
        http_port_list *http;
#if USE_SSL

        https_port_list *https;
#endif

    }

    Sockaddr;
#if SQUID_SNMP

    struct
    {
        char *configFile;
        char *agentInfo;
    }

    Snmp;
#endif
#if USE_WCCP

    struct
    {

        struct in_addr router;

        struct in_addr incoming;

        struct in_addr outgoing;
        int version;
    }

    Wccp;
#endif

    char *as_whois_server;

    struct
    {
        char *log;
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

        int rotateNumber;
    }

    Log;
    char *adminEmail;
    char *effectiveUser;
    char *effectiveGroup;

    struct
    {
#if USE_DNSSERVERS
        char *dnsserver;
#endif

        wordlist *redirect;
#if USE_ICMP

        char *pinger;
#endif
#if USE_UNLINKD

        char *unlinkd;
#endif

        char *diskd;
    }

    Program;
#if USE_DNSSERVERS

    int dnsChildren;
#endif

    int redirectChildren;
    int redirectConcurrency;
    time_t authenticateGCInterval;
    time_t authenticateTTL;
    time_t authenticateIpTTL;

    struct
    {
#if ESI
        char *surrogate_id;
#endif

    }

    Accel;
    char *appendDomain;
    size_t appendDomainLen;
    char *debugOptions;
    char *pidFilename;
    char *mimeTablePathname;
    char *etcHostsPath;
    char *visibleHostname;
    char *uniqueHostname;
    wordlist *hostnameAliases;
    char *errHtmlText;

    struct
    {
        char *host;
        char *file;
        time_t period;
        u_short port;
    }

    Announce;

    struct
    {

        struct in_addr udp_incoming;

        struct in_addr udp_outgoing;
#if SQUID_SNMP

        struct in_addr snmp_incoming;

        struct in_addr snmp_outgoing;
#endif

        struct in_addr client_netmask;
    }

    Addrs;
    size_t tcpRcvBufsz;
    size_t udpMaxHitObjsz;
    wordlist *hierarchy_stoplist;
    wordlist *mcast_group_list;
    wordlist *dns_testname_list;
    wordlist *dns_nameservers;
    peer *peers;
    int npeers;

    struct
    {
        int size;
        int low;
        int high;
    }

    ipcache;

    struct
    {
        int size;
    }

    fqdncache;
    int minDirectHops;
    int minDirectRtt;
    cachemgr_passwd *passwd_list;

    struct
    {
        int objectsPerBucket;
        size_t avgObjectSize;
        size_t maxObjectSize;
        size_t minObjectSize;
        size_t maxInMemObjSize;
    }

    Store;

    struct
    {
        int high;
        int low;
        time_t period;
    }

    Netdb;

    struct
    {
        int log_udp;
#if USE_DNSSERVERS

        int res_defnames;
#endif

        int anonymizer;
        int client_db;
        int query_icmp;
        int icp_hit_stale;
        int buffered_logs;
#if ALLOW_SOURCE_PING

        int source_ping;
#endif

        int common_log;
        int log_mime_hdrs;
        int log_fqdn;
        int announce;
        int mem_pools;
        int test_reachability;
        int half_closed_clients;
#if HTTP_VIOLATIONS

        int reload_into_ims;
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
#if USE_CACHE_DIGESTS

        int digest_generation;
#endif

        int log_ip_on_direct;
        int ie_refresh;
        int vary_ignore_expire;
        int pipeline_prefetch;
#if ESI

        int surrogate_is_remote;
#endif

        int request_entities;
        int check_hostnames;
        int via;
        int emailErrData;
    }

    onoff;
    acl *aclList;

    struct
    {
        acl_access *http;
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

        acl_access *brokenPosts;
#if USE_IDENT

        acl_access *identLookup;
#endif

        acl_access *redirector;
        acl_access *reply;
        acl_address *outgoing_address;
        acl_tos *outgoing_tos;
    }

    accessList;
    acl_deny_info_list *denyInfoList;
    authConfig authConfiguration;

    struct
    {
        size_t list_width;
        int list_wrap;
        char *anon_user;
        int passive;
        int sanitycheck;
    }

    Ftp;
    refresh_t *Refresh;

    struct _cacheSwap
    {
        SwapDir **swapDirs;
        int n_allocated;
        int n_configured;
    }

    cacheSwap;

    struct
    {
        char *directory;
    }

    icons;
    char *errorDirectory;

    struct
    {
        int maxtries;
    }

    retry;

    struct
    {
        size_t limit;
    }

    MemPools;
#if DELAY_POOLS

    DelayConfig Delay;
#endif

    struct
    {
        int icp_average;
        int dns_average;
        int http_average;
        int icp_min_poll;
        int dns_min_poll;
        int http_min_poll;
    }

    comm_incoming;
    int max_open_disk_fds;
    int uri_whitespace;
    size_t rangeOffsetLimit;
#if MULTICAST_MISS_STREAM

    struct
    {

        struct in_addr addr;
        int ttl;
        unsigned short port;
        char *encode_key;
    }

    mcast_miss;
#endif

    header_mangler header_access[HDR_ENUM_END];
    char *coredump_dir;
    char *chroot_dir;
#if USE_CACHE_DIGESTS

    struct
    {
        int bits_per_entry;
        time_t rebuild_period;
        time_t rewrite_period;
        size_t swapout_chunk_size;
        int rebuild_chunk_percentage;
    }

    digest;
#endif
#if USE_SSL

    struct
    {
        int unclean_shutdown;
        char *ssl_engine;
    }

    SSL;
#endif

    wordlist *ext_methods;

    struct
    {
        int high_rptm;
        int high_pf;
        size_t high_memory;
    }

    warnings;
    char *store_dir_select_algorithm;
    int sleep_after_fork;	/* microseconds */
    external_acl *externalAclHelperList;
#if USE_SSL

    struct
    {
        char *cert;
        char *key;
        int version;
        char *options;
        char *cipher;
        char *cafile;
        char *capath;
        char *flags;
        SSL_CTX *sslContext;
    }

    ssl_client;
#endif
};

struct _SquidConfig2
{

    struct
    {
        int enable_purge;
    }

    onoff;
    uid_t effectiveUserID;
    gid_t effectiveGroupID;
};

struct _close_handler
{
    PF *handler;
    void *data;
    close_handler *next;
};

struct _dread_ctrl
{
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int end_of_file;
    DRCB *handler;
    void *client_data;
};

struct _dnsserver_t
{
    int id;
    int inpipe;
    int outpipe;
    time_t answer;
    off_t offset;
    size_t size;
    char ip_inbuf[DNS_INBUF_SZ];

    struct timeval dispatch_time;
    void *data;
};

struct _dwrite_q
{
    off_t file_offset;
    char *buf;
    int len;
    off_t buf_offset;
    dwrite_q *next;
    FREE *free_func;
};


/* ETag support is rudimantal;
 * this struct is likely to change
 * Note: "str" points to memory in HttpHeaderEntry (for now)
 *       so ETags should be used as tmp variables only (for now) */

struct _ETag
{
    const char *str;		/* quoted-string */
    int weak;			/* true if it is a weak validator */
};

struct _fde_disk
{
    DWCB *wrt_handle;
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
    off_t offset;
};

struct _fileMap
{
    int max_n_files;
    int n_files_in_map;
    int toggle;
    int nwords;
    unsigned long *file_map;
};

/* see Packer.c for description */

struct _Packer
{
    /* protected, use interface functions instead */
    append_f append;
    vprintf_f vprintf;
    void *real_handler;		/* first parameter to real append and vprintf */
};

/* http status line */

struct _HttpStatusLine
{
    /* public, read only */
    http_version_t version;
    const char *reason;		/* points to a _constant_ string (default or supplied), never free()d */
    http_status status;
};

/*
 * Note: HttpBody is used only for messages with a small content that is
 * known a priory (e.g., error messages).
 */
#include "MemBuf.h"

struct _HttpBody
{
    /* private */
    MemBuf mb;
};

#include "SquidString.h"
/* http header extention field */

class HttpHdrExtField
{
    String name;		/* field-name  from HTTP/1.1 (no column after name) */
    String value;		/* field-value from HTTP/1.1 */
};

/* http cache control header field */

struct _HttpHdrCc
{
    int mask;
    int max_age;
    int s_maxage;
    int max_stale;
};

/* some fields can hold either time or etag specs (e.g. If-Range) */

struct _TimeOrTag
{
    ETag tag;			/* entity tag */
    time_t time;
    int valid;			/* true if struct is usable */
};

/* per field statistics */

class HttpHeaderFieldStat
{

public:
    HttpHeaderFieldStat() : aliveCount(0), seenCount(0), parsCount(0), errCount(0), repCount(0){}

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
    HttpHeaderFieldInfo() : id (HDR_ACCEPT), type (ftInvalid){}

    http_hdr_type id;
    String name;
    field_type type;
    HttpHeaderFieldStat stat;
};

class HttpHeaderEntry
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    http_hdr_type id;
    String name;
    String value;

private:
    static MemPool *Pool;
};

/* http surogate control header field */

struct _HttpHdrScTarget
{
    dlink_node node;
    int mask;
    int max_age;
    int max_stale;
    String content;
    String target;
};

struct _HttpHdrSc
{
    dlink_list targets;
};

struct _http_state_flags
{

unsigned int proxying:
    1;

unsigned int keepalive:
    1;

unsigned int only_if_cached:
    1;

unsigned int headers_pushed:
    1;

unsigned int front_end_https:
    2;

unsigned int originpeer:
    1;
};

struct _ping_data
{

    struct timeval start;

    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;		/* msec */
    int timedout;
    int w_rtt;
    int p_rtt;
};

struct _HierarchyLogEntry
{
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    ping_data ping;
    char cd_host[SQUIDHOSTNAMELEN];	/* the host of selected by cd peer */
    lookup_t cd_lookup;		/* cd prediction: none, miss, hit */
    int n_choices;		/* #peers we selected from (cd only) */
    int n_ichoices;		/* #peers with known rtt we selected from (cd only) */

    struct timeval peer_select_start;

    struct timeval store_complete_stop;
};

struct _AccessLogEntry
{
    /* NB: memset is used on AccessLogEntries as at 20030715 RBC */
    const char *url;

    struct
    {
        method_t method;
        int code;
        const char *content_type;
        http_version_t version;
    }

    http;

    struct
    {
        icp_opcode opcode;
    }

    icp;

    struct
    {

        struct in_addr caddr;
        size_t size;
        log_type code;
        int msec;
        const char *rfc931;
        const char *authuser;
#if USE_SSL

        const char *ssluser;
#endif

        const char *extuser;

    }

    cache;

    struct
    {
        char *request;
        char *reply;
    }

    headers;

    struct
    {
        const char *method_str;
    }

    _private;
    HierarchyLogEntry hier;
    HttpReply *reply;
    request_t *request;
};

struct _ipcache_addrs
{

    struct in_addr *in_addrs;
    unsigned char *bad_mask;
    unsigned char count;
    unsigned char cur;
    unsigned char badcount;
};

struct _domain_ping
{
    char *domain;
    int do_ping;		/* boolean */
    domain_ping *next;
};

struct _domain_type
{
    char *domain;
    peer_t type;
    domain_type *next;
};

#if USE_CACHE_DIGESTS

struct _Version
{
    short int current;		/* current version */
    short int required;		/* minimal version that can safely handle current version */
};

/* digest control block; used for transmission and storage */

struct _StoreDigestCBlock
{
    Version ver;
    int capacity;
    int count;
    int del_count;
    int mask_size;
    unsigned char bits_per_entry;
    unsigned char hash_func_count;
    short int reserved_short;
    int reserved[32 - 6];
};

struct _DigestFetchState
{
    PeerDigest *pd;
    StoreEntry *entry;
    StoreEntry *old_entry;
    store_client *sc;
    store_client *old_sc;
    request_t *request;
    int offset;
    int mask_offset;
    time_t start_time;
    time_t resp_time;
    time_t expires;

    struct
    {
        int msg;
        int bytes;
    }

    sent, recv;
    char buf[SM_PAGE_SIZE];
    ssize_t bufofs;
    digest_read_state_t state;
};

/* statistics for cache digests and other hit "predictors" */

struct _cd_guess_stats
{
    /* public, read-only */
    int true_hits;
    int false_hits;
    int true_misses;
    int false_misses;
    int close_hits;		/* tmp, remove it later */
};

class PeerDigest
{

public:
    void *operator new (size_t);
    void operator delete(void *);

    struct _peer *peer;			/* pointer back to peer structure, argh */
    CacheDigest *cd;		/* actual digest structure */
    String host;		/* copy of peer->host */
    const char *req_result;	/* text status of the last request */

    struct
    {

unsigned int needed:
        1;	/* there were requests for this digest */

unsigned int usable:
        1;	/* can be used for lookups */

unsigned int requested:
        1;	/* in process of receiving [fresh] digest */
    }

    flags;

    struct
    {
        /* all times are absolute unless augmented with _delay */
        time_t initialized;	/* creation */
        time_t needed;		/* first lookup/use by a peer */
        time_t next_check;	/* next scheduled check/refresh event */
        time_t retry_delay;	/* delay before re-checking _invalid_ digest */
        time_t requested;	/* requested a fresh copy of a digest */
        time_t req_delay;	/* last request response time */
        time_t received;	/* received the current copy of a digest */
        time_t disabled;	/* disabled for good */
    }

    times;

    struct
    {
        cd_guess_stats guess;
        int used_count;

        struct
        {
            int msgs;
            kb_t kbytes;
        }

        sent, recv;
    }

    stats;

private:
    CBDATA_CLASS(PeerDigest);
};

#endif

struct _peer
{
    char *name;
    char *host;
    peer_t type;

    struct sockaddr_in in_addr;

    struct
    {
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
    }

    stats;

    struct
    {
        int version;
        int counts[ICP_END];
        u_short port;
    }

    icp;
#if USE_HTCP

    struct
    {
        double version;
        int counts[2];
        u_short port;
    }

    htcp;
#endif

    u_short http_port;
    domain_ping *peer_domain;
    domain_type *typelist;
    acl_access *access;

    struct
    {

unsigned int proxy_only:
        1;

unsigned int no_query:
        1;

unsigned int background_ping:
        1;

unsigned int no_digest:
        1;

unsigned int default_parent:
        1;

unsigned int roundrobin:
        1;

unsigned int weighted_roundrobin:
        1;

unsigned int mcast_responder:
        1;

unsigned int closest_only:
        1;
#if USE_HTCP

unsigned int htcp:
        1;
#endif

unsigned int no_netdb_exchange:
        1;
#if DELAY_POOLS

unsigned int no_delay:
        1;
#endif

unsigned int allow_miss:
        1;
#if USE_CARP

unsigned int carp:
        1;
#endif

unsigned int originserver:
        1;
    }

    options;
    int weight;
    int basetime;

    struct
    {
        double avg_n_members;
        int n_times_counted;
        int n_replies_expected;
        int ttl;
        int id;

        struct
        {

unsigned int count_event_pending:
            1;

unsigned int counting:
            1;
        }

        flags;
    }

    mcast;
#if USE_CACHE_DIGESTS

    PeerDigest *digest;
    char *digest_url;
#endif

    int tcp_up;			/* 0 if a connect() fails */

    struct in_addr addresses[10];
    int n_addresses;
    int rr_count;
    int rr_lastcount;
    peer *next;
    int test_fd;
#if USE_CARP

    struct
    {
        unsigned int hash;
        double load_multiplier;
        double load_factor;	/* normalized weight value */
    }

    carp;
#endif

    char *login;		/* Proxy authorization */
    time_t connect_timeout;
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
    char *sslflags;
    char *ssldomain;
    SSL_CTX *sslContext;
#endif

    int front_end_https;
};

struct _net_db_name
{
    hash_link hash;		/* must be first */
    net_db_name *next;
    netdbEntry *net_db_entry;
};

struct _net_db_peer
{
    const char *peername;
    double hops;
    double rtt;
    time_t expires;
};

struct _netdbEntry
{
    hash_link hash;		/* must be first */
    char network[16];
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

struct _ps_state
{
    request_t *request;
    StoreEntry *entry;
    int always_direct;
    int never_direct;
    int direct;
    PSC *callback;
    void *callback_data;
    FwdServer *servers;
    /*
     * Why are these struct sockaddr_in instead of peer *?  Because a
     * peer structure can become invalid during the peer selection
     * phase, specifically after a reconfigure.  Thus we need to lookup
     * the peer * based on the address when we are finally ready to
     * reference the peer structure.
     */

    struct sockaddr_in first_parent_miss;

    struct sockaddr_in closest_parent_miss;
    /*
     * ->hit and ->secho can be peer* because they should only be
     * accessed during the thread when they are set
     */
    peer *hit;
    peer_t hit_type;
#if ALLOW_SOURCE_PING

    peer *secho;
#endif

    ping_data ping;
    ACLChecklist *acl_checklist;
};

#if USE_ICMP

struct _pingerEchoData
{

    struct in_addr to;
    unsigned char opcode;
    int psize;
    char payload[PINGER_PAYLOAD_SZ];
};

struct _pingerReplyData
{

    struct in_addr from;
    unsigned char opcode;
    int rtt;
    int hops;
    int psize;
    char payload[PINGER_PAYLOAD_SZ];
};

#endif

struct _iostats
{

    struct
    {
        int reads;
        int reads_deferred;
        int read_hist[16];
        int writes;
        int write_hist[16];
    }

    Http, Ftp, Gopher, Wais;
};

/* Removal policies */

struct _RemovalPolicyNode
{
    void *data;
};

struct _RemovalPolicy
{
    const char *_type;
    void *_data;
    void (*Free) (RemovalPolicy * policy);
    void (*Add) (RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node);
    void (*Remove) (RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node);
    void (*Referenced) (RemovalPolicy * policy, const StoreEntry * entry, RemovalPolicyNode * node);
    void (*Dereferenced) (RemovalPolicy * policy, const StoreEntry * entry, RemovalPolicyNode * node);
    RemovalPolicyWalker *(*WalkInit) (RemovalPolicy * policy);
    RemovalPurgeWalker *(*PurgeInit) (RemovalPolicy * policy, int max_scan);
    void (*Stats) (RemovalPolicy * policy, StoreEntry * entry);
};

struct _RemovalPolicyWalker
{
    RemovalPolicy *_policy;
    void *_data;
    const StoreEntry *(*Next) (RemovalPolicyWalker * walker);
    void (*Done) (RemovalPolicyWalker * walker);
};

struct _RemovalPurgeWalker
{
    RemovalPolicy *_policy;
    void *_data;
    int scanned, max_scan, locked;
    StoreEntry *(*Next) (RemovalPurgeWalker * walker);
    void (*Done) (RemovalPurgeWalker * walker);
};

struct request_flags
{
    request_flags():range(0),nocache(0),ims(0),auth(0),cachable(0),hierarchical(0),loopdetect(0),proxy_keepalive(0),proxying(0),refresh(0),redirected(0),need_validation(0),accelerated(0),transparent(0),internal(0),internalclient(0),body_sent(0),destinationIPLookedUp_(0)
    {
#if HTTP_VIOLATIONS
        nocache_hack = 1;
#endif

    }

unsigned int range:
    1;

unsigned int nocache:
    1;

unsigned int ims:
    1;

unsigned int auth:
    1;

unsigned int cachable:
    1;

unsigned int hierarchical:
    1;

unsigned int loopdetect:
    1;

unsigned int proxy_keepalive:
    1;

unsigned int proxying:
    1;	/* this should be killed, also in httpstateflags */

unsigned int refresh:
    1;

unsigned int redirected:
    1;

unsigned int need_validation:
    1;
#if HTTP_VIOLATIONS

unsigned int nocache_hack:
    1;	/* for changing/ignoring no-cache requests */
#endif

unsigned int accelerated:
    1;

unsigned int transparent:
    1;

unsigned int internal:
    1;

unsigned int internalclient:
    1;

unsigned int body_sent:
    1;
    bool resetTCP() const;
    void setResetTCP();
    void clearResetTCP();
    void destinationIPLookupCompleted();
    bool destinationIPLookedUp() const;

private:

unsigned int reset_tcp:
    1;

unsigned int destinationIPLookedUp_:
    1;
};

struct _link_list
{
    void *ptr;

    struct _link_list *next;
};

struct _cachemgr_passwd
{
    char *passwd;
    wordlist *actions;
    cachemgr_passwd *next;
};

struct _refresh_t
{
    const char *pattern;
    regex_t compiled_pattern;
    time_t min;
    double pct;
    time_t max;
    refresh_t *next;

    struct
    {

unsigned int icase:
        1;
#if HTTP_VIOLATIONS

unsigned int override_expire:
        1;

unsigned int override_lastmod:
        1;

unsigned int reload_into_ims:
        1;

unsigned int ignore_reload:
        1;
#endif

    }

    flags;
};

struct _CommWriteStateData
{
    char *buf;
    size_t size;
    off_t offset;
    CWCB *handler;
    void *handler_data;
    FREE *free_func;
};

struct _ErrorState
{
    err_type type;
    int page_id;
    http_status httpStatus;
    auth_user_request_t *auth_user_request;
    request_t *request;
    char *url;
    int xerrno;
    char *host;
    u_short port;
    char *dnsserver_msg;
    time_t ttl;

    struct in_addr src_addr;
    char *redirect_url;
    ERCB *callback;
    void *callback_data;

    struct
    {

unsigned int flag_cbdata:
        1;
    }

    flags;

    struct
    {
        wordlist *server_msg;
        char *request;
        char *reply;
    }

    ftp;
    char *request_hdrs;
    char *err_msg; /* Preformatted error message from the cache */
};

/*
 * "very generic" histogram; 
 * see important comments on hbase_f restrictions in StatHist.c
 */

struct _StatHist
{
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

struct _StatCounters
{

    struct
    {
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
    }

    client_http;

    struct
    {

        struct
        {
            int requests;
            int errors;
            kb_t kbytes_in;
            kb_t kbytes_out;
        }

        all , http, ftp, other;
    }

    server;

    struct
    {
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
    }

    icp;

    struct
    {
        int pkts_sent;
        int pkts_recv;
    }

    htcp;

    struct
    {
        int requests;
    }

    unlink;

    struct
    {
        StatHist svc_time;
    }

    dns;

    struct
    {
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
    }

    cd;

    struct
    {
        int times_used;
    }

    netdb;
    int page_faults;
    int select_loops;
    int select_fds;
    double select_time;
    double cputime;

    struct timeval timestamp;
    StatHist comm_icp_incoming;
    StatHist comm_dns_incoming;
    StatHist comm_http_incoming;
    StatHist select_fds_hist;

    struct
    {

        struct
        {
            int opens;
            int closes;
            int reads;
            int writes;
            int seeks;
            int unlinks;
        }

        disk;

        struct
        {
            int accepts;
            int sockets;
            int connects;
            int binds;
            int closes;
            int reads;
            int writes;
            int recvfroms;
            int sendtos;
        }

        sock;
#if HAVE_POLL

        int polls;
#else

        int selects;
#endif

    }

    syscalls;
    int aborted_requests;

    struct
    {
        int files_cleaned;
        int outs;
        int ins;
    }

    swap;
};

/* per header statistics */

struct _HttpHeaderStat
{
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


struct _ClientInfo
{
    hash_link hash;		/* must be first */

    struct in_addr addr;

    struct
    {
        int result_hist[LOG_TYPE_MAX];
        int n_requests;
        kb_t kbytes_in;
        kb_t kbytes_out;
        kb_t hit_kbytes_out;
    }

    Http, Icp;

    struct
    {
        time_t time;
        int n_req;
        int n_denied;
    }

    cutoff;
    int n_established;		/* number of current established connections */
};

struct _CacheDigest
{
    /* public, read-only */
    char *mask;			/* bit mask */
    size_t mask_size;		/* mask size in bytes */
    int capacity;		/* expected maximum for .count, not a hard limit */
    int bits_per_entry;		/* number of bits allocated for each entry from capacity */
    int count;			/* number of digested entries */
    int del_count;		/* number of deletions performed so far */
};

struct _FwdServer
{
    peer *_peer;		/* NULL --> origin server */
    hier_code code;
    FwdServer *next;
};

struct _FwdState
{
    int client_fd;
    StoreEntry *entry;
    request_t *request;
    FwdServer *servers;
    int server_fd;
    ErrorState *err;
    time_t start;
    int n_tries;
#if WIP_FWD_LOG

    http_status last_status;
#endif

    struct
    {

unsigned int dont_retry:
        1;

unsigned int ftp_pasv_failed:
        1;
    }

    flags;
};

class helper_request;

struct _helper
{
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    int n_to_start;
    int n_running;
    int ipc_type;
    unsigned int concurrency;
    time_t last_queue_warn;

    struct
    {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    }

    stats;
};

struct _helper_stateful
{
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    int n_to_start;
    int n_running;
    int ipc_type;
    MemPool *datapool;
    HLPSAVAIL *IsAvailable;
    HLPSONEQ *OnEmptyQueue;
    time_t last_queue_warn;

    struct
    {
        int requests;
        int replies;
        int queue_size;
        int avg_svc_time;
    }

    stats;
};

struct _helper_server
{
    int index;
    int pid;
    int rfd;
    int wfd;
    MemBuf wqueue;
    MemBuf writebuf;
    char *rbuf;
    size_t rbuf_sz;
    off_t roffset;

    dlink_node link;
    helper *parent;
    helper_request **requests;

    struct _helper_flags
    {

unsigned int writing:
        1;

unsigned int alive:
        1;

unsigned int closing:
        1;

unsigned int shutdown:
        1;
    }

    flags;

    struct
    {
        int uses;
        unsigned int pending;
    }

    stats;
};

class helper_stateful_request;

struct _helper_stateful_server
{
    int index;
    int pid;
    int rfd;
    int wfd;
    /* MemBuf wqueue; */
    /* MemBuf writebuf; */
    char *rbuf;
    size_t rbuf_sz;
    off_t roffset;

    struct timeval dispatch_time;

    struct timeval answer_time;
    dlink_node link;
    dlink_list queue;
    statefulhelper *parent;
    helper_stateful_request *request;

    struct _helper_stateful_flags
    {

unsigned int alive:
        1;

unsigned int busy:
        1;

unsigned int closing:
        1;

unsigned int shutdown:
        1;
        stateful_helper_reserve_t reserved;
    }

    flags;

    struct
    {
        int uses;
        int submits;
        int releases;
        int deferbyfunc;
        int deferbycb;
    }

    stats;
    int deferred_requests;	/* current number of deferred requests */
    void *data;			/* State data used by the calling routines */
};

/*
 * use this when you need to pass callback data to a blocking
 * operation, but you don't want to add that pointer to cbdata
 */

struct _generic_cbdata
{
    void *data;
};

struct _store_rebuild_data
{
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

/*
 * This defines an repl type
 */

struct _storerepl_entry
{
    const char *typestr;
    REMOVALPOLICYCREATE *create;
};

/*
 * Async disk IO - this defines a async disk io queue
 */

struct _diskd_queue
{
    int smsgid;			/* send sysvmsg id */
    int rmsgid;			/* recv sysvmsg id */
    int wfd;			/* queue file descriptor ? */
    int away;			/* number of requests away */
    int sent_count;		/* number of messages sent */
    int recv_count;		/* number of messages received */

    struct
    {
        char *buf;		/* shm buffer */
        link_list *stack;
        int id;			/* sysvshm id */
    }

    shm;
};

struct _Logfile
{
    int fd;
    char path[MAXPATHLEN];
    char *buf;
    size_t bufsz;
    off_t offset;

    struct
    {

unsigned int fatal:
        1;
    }

    flags;
};

struct _logformat
{
    char *name;
    logformat_token *format;
    logformat *next;
};

struct _customlog
{
    char *filename;
    acl_list *aclList;
    logformat *logFormat;
    Logfile *logfile;
    customlog *next;
    customlog_type type;
};

struct cache_dir_option
{
    const char *name;
    void (*parse) (SwapDir * sd, const char *option, const char *value, int reconfiguring);
    void (*dump) (StoreEntry * e, const char *option, SwapDir const * sd);
};

#endif /* SQUID_STRUCTS_H */
