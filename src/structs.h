
/*
 * $Id: structs.h,v 1.312 2000/01/14 08:37:08 wessels Exp $
 *
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

struct _dlink_node {
    void *data;
    dlink_node *prev;
    dlink_node *next;
};

struct _dlink_list {
    dlink_node *head;
    dlink_node *tail;
};

struct _acl_ip_data {
    struct in_addr addr1;	/* if addr2 non-zero then its a range */
    struct in_addr addr2;
    struct in_addr mask;
    acl_ip_data *next;		/* used for parsing, not for storing */
};

struct _acl_snmp_comm {
    char *name;
    void *community;
    acl_snmp_comm *next;
};

struct _acl_time_data {
    int weekbits;
    int start;
    int stop;
    acl_time_data *next;
};

struct _acl_name_list {
    char name[ACL_NAME_SZ];
    acl_name_list *next;
};

struct _acl_proxy_auth_user {
    /* first two items must be same as hash_link */
    char *user;
    acl_proxy_auth_user *next;
    /* extra fields for proxy_auth */
    char *passwd;
    int passwd_ok;		/* 1 = passwd checked OK */
    long expiretime;
    struct in_addr ipaddr;	/* IP addr this user authenticated from */
    time_t ip_expiretime;
};

struct _acl_deny_info_list {
    int err_page_id;
    char *err_page_name;
    acl_name_list *acl_list;
    acl_deny_info_list *next;
};

#if USE_ARP_ACL

struct _acl_arp_data {
    char eth[6];
};

#endif

struct _String {
    /* never reference these directly! */
    unsigned short int size;	/* buffer size; 64K limit */
    unsigned short int len;	/* current length  */
    char *buf;
};

#if SQUID_SNMP

struct _snmp_request_t {
    u_char *buf;
    u_char *outbuf;
    int len;
    int sock;
    long reqid;
    int outlen;
    struct sockaddr_in from;
    struct snmp_pdu *PDU;
    aclCheck_t *acl_checklist;
    u_char *community;
};

#endif

struct _acl {
    char name[ACL_NAME_SZ];
    squid_acl type;
    void *data;
    char *cfgline;
    acl *next;
};

struct _acl_list {
    int op;
    acl *acl;
    acl_list *next;
};

struct _acl_access {
    int allow;
    acl_list *acl_list;
    char *cfgline;
    acl_access *next;
};

struct _aclCheck_t {
    const acl_access *access_list;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct in_addr my_addr;
    unsigned short my_port;
    request_t *request;
#if USE_IDENT
    ConnStateData *conn;	/* hack for ident */
    char ident[USER_IDENT_SZ];
#endif
    acl_proxy_auth_user *auth_user;
    acl_lookup_state state[ACL_ENUM_MAX];
#if SQUID_SNMP
    char *snmp_community;
#endif
    PF *callback;
    void *callback_data;
};

struct _aio_result_t {
    int aio_return;
    int aio_errno;
};

struct _wordlist {
    char *key;
    wordlist *next;
};

struct _intlist {
    int i;
    intlist *next;
};

struct _intrange {
    int i;
    int j;
    intrange *next;
};

struct _ushortlist {
    u_short i;
    ushortlist *next;
};

struct _relist {
    char *pattern;
    regex_t regex;
    relist *next;
};

struct _sockaddr_in_list {
    struct sockaddr_in s;
    sockaddr_in_list *next;
};

#if DELAY_POOLS
struct _delaySpec {
    int restore_bps;
    int max_bytes;
};

/* malloc()'d only as far as used (class * sizeof(delaySpec)!
 * order of elements very important!
 */
struct _delaySpecSet {
    delaySpec aggregate;
    delaySpec individual;
    delaySpec network;
};

struct _delayConfig {
    unsigned short pools;
    unsigned short initial;
    unsigned char *class;
    delaySpecSet **rates;
    acl_access **access;
};

#endif

struct _SquidConfig {
    struct {
	size_t maxSize;
	int highWaterMark;
	int lowWaterMark;
    } Swap;
    size_t memMaxSize;
    struct {
	char *relayHost;
	u_short relayPort;
	peer *peer;
    } Wais;
    struct {
	size_t min;
	int pct;
	size_t max;
    } quickAbort;
#if HEAP_REPLACEMENT
    char *replPolicy;
#else
    /* 
     * Note: the non-LRU policies do not use referenceAge, but we cannot
     * remove it until we find out how to implement #else for cf_parser.c
     */
#endif
    time_t referenceAge;
    time_t negativeTtl;
    time_t negativeDnsTtl;
    time_t positiveDnsTtl;
    time_t shutdownLifetime;
    struct {
	time_t read;
	time_t lifetime;
	time_t connect;
	time_t peer_connect;
	time_t request;
	time_t pconn;
	time_t siteSelect;
	time_t deadPeer;
	int icp_query;		/* msec */
	int icp_query_max;	/* msec */
	int mcast_icp_query;	/* msec */
#if USE_IDENT
	time_t ident;
#endif
    } Timeout;
    size_t maxRequestHeaderSize;
    size_t maxRequestBodySize;
    size_t maxReplyBodySize;
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
	sockaddr_in_list *http;
    } Sockaddr;
#if SQUID_SNMP
    struct {
	char *configFile;
	char *agentInfo;
    } Snmp;
#endif
#if USE_WCCP
    struct {
	struct in_addr router;
	struct in_addr incoming;
	struct in_addr outgoing;
    } Wccp;
#endif
    char *as_whois_server;
    struct {
	char *log;
	char *access;
	char *store;
	char *swap;
	char *useragent;
	int rotateNumber;
    } Log;
    char *adminEmail;
    char *effectiveUser;
    char *effectiveGroup;
    struct {
	char *dnsserver;
	wordlist *redirect;
	wordlist *authenticate;
	char *pinger;
	char *unlinkd;
    } Program;
    int dnsChildren;
    int redirectChildren;
    int authenticateChildren;
    int authenticateTTL;
    int authenticateIpTTL;
    struct {
	char *host;
	u_short port;
    } Accel;
    char *appendDomain;
    size_t appendDomainLen;
    char *debugOptions;
    char *pidFilename;
    char *mimeTablePathname;
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
	struct in_addr tcp_outgoing;
	struct in_addr udp_incoming;
	struct in_addr udp_outgoing;
#if SQUID_SNMP
	struct in_addr snmp_incoming;
	struct in_addr snmp_outgoing;
#endif
	struct in_addr client_netmask;
    } Addrs;
    size_t tcpRcvBufsz;
    size_t udpMaxHitObjsz;
    wordlist *hierarchy_stoplist;
    wordlist *mcast_group_list;
    wordlist *dns_testname_list;
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
    cachemgr_passwd *passwd_list;
    struct {
	int objectsPerBucket;
	size_t avgObjectSize;
	size_t maxObjectSize;
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
#if ALLOW_SOURCE_PING
	int source_ping;
#endif
	int common_log;
	int log_mime_hdrs;
	int log_fqdn;
	int announce;
	int accel_with_proxy;
	int mem_pools;
	int test_reachability;
	int half_closed_clients;
#if HTTP_VIOLATIONS
	int reload_into_ims;
#endif
	int offline;
	int redir_rewrites_host;
	int prefer_direct;
	int strip_query_terms;
	int redirector_bypass;
	int ignore_unknown_nameservers;
#if USE_CACHE_DIGESTS
	int digest_generation;
#endif
    } onoff;
    acl *aclList;
    struct {
	acl_access *http;
	acl_access *icp;
	acl_access *miss;
	acl_access *NeverDirect;
	acl_access *AlwaysDirect;
	acl_access *ASlists;
	acl_access *noCache;
#if SQUID_SNMP
	acl_access *snmp;
#endif
	acl_access *brokenPosts;
#if USE_IDENT
	acl_access *identLookup;
#endif
	acl_access *redirector;
    } accessList;
    acl_deny_info_list *denyInfoList;
    char *proxyAuthRealm;
    struct {
	size_t list_width;
	int list_wrap;
	char *anon_user;
    } Ftp;
    refresh_t *Refresh;
    struct _cacheSwap {
	SwapDir *swapDirs;
	int n_allocated;
	int n_configured;
    } cacheSwap;
    char *fake_ua;
    struct {
	char *directory;
    } icons;
    char *errorDirectory;
    struct {
	time_t timeout;
	int maxtries;
    } retry;
    struct {
	size_t limit;
    } MemPools;
#if DELAY_POOLS
    delayConfig Delay;
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
    size_t rangeOffsetLimit;
#if MULTICAST_MISS_STREAM
    struct {
	struct in_addr addr;
	int ttl;
	unsigned short port;
	char *encode_key;
    } mcast_miss;
#endif
    HttpHeaderMask anonymize_headers;
    char *coredump_dir;
#if USE_CACHE_DIGESTS
    struct {
	int bits_per_entry;
	int rebuild_period;
	int rewrite_period;
	int swapout_chunk_size;
	int rebuild_chunk_percentage;
    } digest;
#endif
};

struct _SquidConfig2 {
    struct {
	char *prefix;
	int on;
    } Accel;
    struct {
	int enable_purge;
    } onoff;
};

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

struct _dnsserver_t {
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

struct _dnsStatData {
    int requests;
    int replies;
    int hist[DefaultDnsChildrenMax];
};

struct _dwrite_q {
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
struct _ETag {
    const char *str;		/* quoted-string */
    int weak;			/* true if it is a weak validator */
};

struct _fde {
    unsigned int type;
    u_short local_port;
    u_short remote_port;
    char ipaddr[16];		/* dotted decimal address of peer */
    char desc[FD_DESC_SZ];
    struct {
	unsigned int open:1;
	unsigned int close_request:1;
	unsigned int write_daemon:1;
	unsigned int closing:1;
	unsigned int socket_eof:1;
	unsigned int nolinger:1;
	unsigned int nonblocking:1;
	unsigned int ipc:1;
	unsigned int called_connect:1;
    } flags;
    int bytes_read;
    int bytes_written;
    int uses;			/* ie # req's over persistent conn */
    struct _fde_disk {
	DWCB *wrt_handle;
	void *wrt_handle_data;
	dwrite_q *write_q;
	dwrite_q *write_q_tail;
	off_t offset;
    } disk;
    PF *read_handler;
    void *read_data;
    PF *write_handler;
    void *write_data;
    PF *timeout_handler;
    time_t timeout;
    void *timeout_data;
    void *lifetime_data;
    close_handler *close_handler;	/* linked list */
    DEFER *defer_check;		/* check if we should defer read */
    void *defer_data;
    CommWriteStateData *rwstate;	/* State data for comm_write */
};

struct _fileMap {
    int max_n_files;
    int n_files_in_map;
    int toggle;
    int nwords;
    unsigned long *file_map;
};

/* auto-growing memory-resident buffer with printf interface */
/* note: when updating this struct, update MemBufNULL #define */
struct _MemBuf {
    /* public, read-only */
    char *buf;
    mb_size_t size;		/* used space, does not count 0-terminator */

    /* private, stay away; use interface function instead */
    mb_size_t max_capacity;	/* when grows: assert(new_capacity <= max_capacity) */
    mb_size_t capacity;		/* allocated space */
    FREE *freefunc;		/* what to use to free the buffer, NULL after memBufFreeFunc() is called */
};

/* see Packer.c for description */
struct _Packer {
    /* protected, use interface functions instead */
    append_f append;
    vprintf_f vprintf;
    void *real_handler;		/* first parameter to real append and vprintf */
};

/* http status line */
struct _HttpStatusLine {
    /* public, read only */
    float version;
    const char *reason;		/* points to a _constant_ string (default or supplied), never free()d */
    http_status status;
};

/*
 * Note: HttpBody is used only for messages with a small content that is
 * known a priory (e.g., error messages).
 */
struct _HttpBody {
    /* private */
    MemBuf mb;
};

/* http header extention field */
struct _HttpHdrExtField {
    String name;		/* field-name  from HTTP/1.1 (no column after name) */
    String value;		/* field-value from HTTP/1.1 */
};

/* http cache control header field */
struct _HttpHdrCc {
    int mask;
    int max_age;
    int s_maxage;
};

/* http byte-range-spec */
struct _HttpHdrRangeSpec {
    ssize_t offset;
    ssize_t length;
};

/* There may be more than one byte range specified in the request.
 * This object holds all range specs in order of their appearence
 * in the request because we SHOULD preserve that order.
 */
struct _HttpHdrRange {
    Stack specs;
};

/* http content-range header field */
struct _HttpHdrContRange {
    HttpHdrRangeSpec spec;
    ssize_t elength;		/* entity length, not content length */
};

/* some fields can hold either time or etag specs (e.g. If-Range) */
struct _TimeOrTag {
    ETag tag;			/* entity tag */
    time_t time;
    int valid;			/* true if struct is usable */
};

/* data for iterating thru range specs */
struct _HttpHdrRangeIter {
    HttpHdrRangePos pos;
    const HttpHdrRangeSpec *spec;	/* current spec at pos */
    ssize_t debt_size;		/* bytes left to send from the current spec */
    ssize_t prefix_size;	/* the size of the incoming HTTP msg prefix */
    String boundary;		/* boundary for multipart responses */
};

/* constant attributes of http header fields */
struct _HttpHeaderFieldAttrs {
    const char *name;
    http_hdr_type id;
    field_type type;
};

/* per field statistics */
struct _HttpHeaderFieldStat {
    int aliveCount;		/* created but not destroyed (count) */
    int seenCount;		/* #fields we've seen */
    int parsCount;		/* #parsing attempts */
    int errCount;		/* #pasring errors */
    int repCount;		/* #repetitons */
};

/* compiled version of HttpHeaderFieldAttrs plus stats */
struct _HttpHeaderFieldInfo {
    http_hdr_type id;
    String name;
    field_type type;
    HttpHeaderFieldStat stat;
};

struct _HttpHeaderEntry {
    http_hdr_type id;
    String name;
    String value;
};

struct _HttpHeader {
    /* protected, do not use these, use interface functions instead */
    Array entries;		/* parsed fields in raw format */
    HttpHeaderMask mask;	/* bit set <=> entry present */
    http_hdr_owner_type owner;	/* request or reply */
    int len;			/* length when packed, not counting terminating '\0' */
};

struct _HttpReply {
    /* unsupported, writable, may disappear/change in the future */
    int hdr_sz;			/* sums _stored_ status-line, headers, and <CRLF> */

    /* public, readable; never update these or their .hdr equivalents directly */
    int content_length;
    time_t date;
    time_t last_modified;
    time_t expires;
    String content_type;
    HttpHdrCc *cache_control;
    HttpHdrContRange *content_range;
    short int keep_alive;

    /* public, readable */
    HttpMsgParseState pstate;	/* the current parsing state */

    /* public, writable, but use httpReply* interfaces when possible */
    HttpStatusLine sline;
    HttpHeader header;
    HttpBody body;		/* for small constant memory-resident text bodies only */
};

struct _http_state_flags {
    unsigned int proxying:1;
    unsigned int keepalive:1;
    unsigned int only_if_cached:1;
};

struct _HttpStateData {
    StoreEntry *entry;
    request_t *request;
    char *reply_hdr;
    int reply_hdr_state;
    peer *peer;			/* peer request made to */
    int eof;			/* reached end-of-object? */
    request_t *orig_request;
    int fd;
    http_state_flags flags;
    FwdState *fwd;
};

struct _icpUdpData {
    struct sockaddr_in address;
    void *msg;
    size_t len;
    icpUdpData *next;
#ifndef LESS_TIMING
    struct timeval start;
#endif
    log_type logcode;
    struct timeval queue_time;
};

struct _ping_data {
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

struct _HierarchyLogEntry {
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    ping_data ping;
    char cd_host[SQUIDHOSTNAMELEN];	/* the host of selected by cd peer */
    peer_select_alg_t alg;	/* peer selection algorithm */
    lookup_t cd_lookup;		/* cd prediction: none, miss, hit */
    int n_choices;		/* #peers we selected from (cd only) */
    int n_ichoices;		/* #peers with known rtt we selected from (cd only) */
    struct timeval peer_select_start;
    struct timeval store_complete_stop;
};

struct _AccessLogEntry {
    const char *url;
    struct {
	method_t method;
	int code;
	const char *content_type;
	float version;
    } http;
    struct {
	icp_opcode opcode;
    } icp;
    struct {
	struct in_addr caddr;
	size_t size;
	log_type code;
	int msec;
	const char *ident;
    } cache;
    struct {
	char *request;
	char *reply;
    } headers;
    struct {
	const char *method_str;
    } private;
    HierarchyLogEntry hier;
};

struct _clientHttpRequest {
    ConnStateData *conn;
    request_t *request;		/* Parsed URL ... */
    char *uri;
    char *log_uri;
    struct {
	off_t offset;
	size_t size;
    } out;
    HttpHdrRangeIter range_iter;	/* data for iterating thru range specs */
    size_t req_sz;		/* raw request size on input, not current request size */
    StoreEntry *entry;
    StoreEntry *old_entry;
    log_type log_type;
#if USE_CACHE_DIGESTS
    const char *lookup_type;	/* temporary hack: storeGet() result: HIT/MISS/NONE */
#endif
    http_status http_code;
    struct timeval start;
    float http_ver;
    int redirect_state;
    aclCheck_t *acl_checklist;	/* need ptr back so we can unreg if needed */
    clientHttpRequest *next;
    AccessLogEntry al;
    struct {
	unsigned int accel:1;
	unsigned int internal:1;
	unsigned int done_copying:1;
    } flags;
    struct {
	http_status status;
	char *location;
    } redirect;
    dlink_node active;
};

struct _ConnStateData {
    int fd;
    struct {
	char *buf;
	off_t offset;
	size_t size;
    } in;
    clientHttpRequest *chr;
    struct sockaddr_in peer;
    struct sockaddr_in me;
    struct in_addr log_addr;
    char ident[USER_IDENT_SZ];
    int nrequests;
    int persistent;
    struct {
	int n;
	time_t until;
    } defer;
};

struct _ipcache_addrs {
    struct in_addr *in_addrs;
    unsigned char *bad_mask;
    unsigned char count;
    unsigned char cur;
    unsigned char badcount;
};

struct _ip_pending {
    IPH *handler;
    void *handlerData;
    ip_pending *next;
};

struct _ipcache_entry {
    /* first two items must be equivalent to hash_link */
    char *name;
    ipcache_entry *next;
    time_t lastref;
    time_t expires;
    ipcache_addrs addrs;
    ip_pending *pending_head;
    char *error_message;
    struct timeval request_time;
    dlink_node lru;
    u_char locks;
    ipcache_status_t status:3;
};

struct _fqdn_pending {
    FQDNH *handler;
    void *handlerData;
    fqdn_pending *next;
};

struct _fqdncache_entry {
    /* first two items must be equivalent to hash_link */
    char *name;
    fqdncache_entry *next;
    time_t lastref;
    time_t expires;
    unsigned char name_count;
    char *names[FQDN_MAX_NAMES + 1];
    fqdn_pending *pending_head;
    char *error_message;
    struct timeval request_time;
    dlink_node lru;
    unsigned char locks;
    fqdncache_status_t status:3;
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
struct _Version {
    short int current;		/* current version */
    short int required;		/* minimal version that can safely handle current version */
};

/* digest control block; used for transmission and storage */
struct _StoreDigestCBlock {
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

struct _DigestFetchState {
    PeerDigest *pd;
    StoreEntry *entry;
    StoreEntry *old_entry;
    request_t *request;
    int offset;
    int mask_offset;
    time_t start_time;
    time_t resp_time;
    time_t expires;
    struct {
	int msg;
	int bytes;
    } sent, recv;
};

/* statistics for cache digests and other hit "predictors" */
struct _cd_guess_stats {
    /* public, read-only */
    int true_hits;
    int false_hits;
    int true_misses;
    int false_misses;
    int close_hits;		/* tmp, remove it later */
};

struct _PeerDigest {
    peer *peer;			/* pointer back to peer structure, argh */
    CacheDigest *cd;		/* actual digest structure */
    String host;		/* copy of peer->host */
    const char *req_result;	/* text status of the last request */
    struct {
	unsigned int needed:1;	/* there were requests for this digest */
	unsigned int usable:1;	/* can be used for lookups */
	unsigned int requested:1;	/* in process of receiving [fresh] digest */
    } flags;
    struct {
	/* all times are absolute unless augmented with _delay */
	time_t initialized;	/* creation */
	time_t needed;		/* first lookup/use by a peer */
	time_t next_check;	/* next scheduled check/refresh event */
	time_t retry_delay;	/* delay before re-checking _invalid_ digest */
	time_t requested;	/* requested a fresh copy of a digest */
	time_t req_delay;	/* last request response time */
	time_t received;	/* received the current copy of a digest */
	time_t disabled;	/* disabled for good */
    } times;
    struct {
	cd_guess_stats guess;
	int used_count;
	struct {
	    int msgs;
	    kb_t kbytes;
	} sent, recv;
    } stats;
};

#endif

struct _peer {
    char *host;
    peer_t type;
    struct sockaddr_in in_addr;
    struct {
	int pings_sent;
	int pings_acked;
	int fetches;
	int rtt;
	int ignored_replies;
	int n_keepalives_sent;
	int n_keepalives_recv;
	time_t last_query;
	time_t last_reply;
	int logged_state;	/* so we can print dead/revived msgs */
    } stats;
    struct {
	int version;
	int counts[ICP_END];
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
	unsigned int no_digest:1;
	unsigned int default_parent:1;
	unsigned int roundrobin:1;
	unsigned int mcast_responder:1;
	unsigned int closest_only:1;
#if USE_HTCP
	unsigned int htcp:1;
#endif
	unsigned int no_netdb_exchange:1;
#if DELAY_POOLS
	unsigned int no_delay:1;
#endif
    } options;
    int weight;
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
    time_t last_fail_time;
    struct in_addr addresses[10];
    int n_addresses;
    int rr_count;
    peer *next;
    int test_fd;
#if USE_CARP
    struct {
	unsigned long hash;
	unsigned long load_multiplier;
	float load_factor;
    } carp;
#endif
    char *login;		/* Proxy authorization */
    time_t connect_timeout;
};

struct _net_db_name {
    char *name;
    net_db_name *htbl_next;
    net_db_name *next;
    netdbEntry *net_db_entry;
};

struct _net_db_peer {
    char *peername;
    double hops;
    double rtt;
    time_t expires;
};

struct _netdbEntry {
    /* first two items must be equivalent to hash_link */
    char *key;
    netdbEntry *next;
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

struct _ps_state {
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
    aclCheck_t *acl_checklist;
};

struct _pingerEchoData {
    struct in_addr to;
    unsigned char opcode;
    int psize;
    char payload[PINGER_PAYLOAD_SZ];
};

struct _pingerReplyData {
    struct in_addr from;
    unsigned char opcode;
    int rtt;
    int hops;
    int psize;
    char payload[PINGER_PAYLOAD_SZ];
};

struct _icp_common_t {
    unsigned char opcode;	/* opcode */
    unsigned char version;	/* version number */
    unsigned short length;	/* total length (bytes) */
    u_num32 reqnum;		/* req number (req'd for UDP) */
    u_num32 flags;
    u_num32 pad;
    u_num32 shostid;		/* sender host id */
};

struct _iostats {
    struct {
	int reads;
	int reads_deferred;
	int read_hist[16];
	int writes;
	int write_hist[16];
    } Http, Ftp, Gopher, Wais;
};

struct _mem_node {
    char *data;
    int len;
    mem_node *next;
};

struct _mem_hdr {
    mem_node *head;
    mem_node *tail;
    int origin_offset;
};

/* keep track each client receiving data from that particular StoreEntry */
struct _store_client {
    int type;
    off_t copy_offset;
    off_t seen_offset;
    size_t copy_size;
    char *copy_buf;
    STCB *callback;
    void *callback_data;
    StoreEntry *entry;		/* ptr to the parent StoreEntry, argh! */
    storeIOState *swapin_sio;
    struct {
	unsigned int disk_io_pending:1;
	unsigned int store_copying:1;
	unsigned int copy_event_pending:1;
    } flags;
    store_client *next;
#if DELAY_POOLS
    delay_id delay_id;
#endif
};


/* This structure can be freed while object is purged out from memory */
struct _MemObject {
    method_t method;
    char *url;
    mem_hdr data_hdr;
    off_t inmem_hi;
    off_t inmem_lo;
    store_client *clients;
    int nclients;
    struct {
	off_t queue_offset;	/* relative to in-mem data */
	storeIOState *sio;
    } swapout;
    HttpReply *reply;
    request_t *request;
    struct timeval start_ping;
    IRCB *ping_reply_callback;
    void *ircb_data;
    int fd;			/* FD of client creating this entry */
    struct {
	STABH *callback;
	void *data;
    } abort;
    char *log_url;
#if HEAP_REPLACEMENT
    /* 
     * A MemObject knows where it is in the in-memory heap.
     */
    heap_node *node;
#else
    dlink_node lru;
#endif
    int id;
    ssize_t object_sz;
    size_t swap_hdr_sz;
#if URL_CHECKSUM_DEBUG
    unsigned int chksum;
#endif
};

struct _StoreEntry {
    /* first two items must be same as hash_link */
    const cache_key *key;
    StoreEntry *next;
    MemObject *mem_obj;
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    size_t swap_file_sz;
    u_short refcount;
    u_short flags;
    sfileno swap_file_number;
#if HEAP_REPLACEMENT
    heap_node *node;
#else
    dlink_node lru;
#endif
    u_short lock_count;		/* Assume < 65536! */
    mem_status_t mem_status:3;
    ping_status_t ping_status:3;
    store_status_t store_status:3;
    swap_status_t swap_status:3;
};

struct _SwapDir {
    swapdir_t type;
    fileMap *map;
    int cur_size;
    int high_size;
    int max_size;
    char *path;
    int index;			/* This entry's index into the swapDirs array */
    sfileno suggest;
    int removals;
    int scanned;
    struct {
	unsigned int selected:1;
	unsigned int read_only:1;
    } flags;
    STINIT *init;
    STNEWFS *newfs;
    struct {
	STOBJOPEN *open;
	STOBJCLOSE *close;
	STOBJREAD *read;
	STOBJWRITE *write;
	STOBJUNLINK *unlink;
    } obj;
    struct {
	STLOGOPEN *open;
	STLOGCLOSE *close;
	STLOGWRITE *write;
	struct {
	    STLOGCLEANOPEN *open;
	    STLOGCLEANWRITE *write;
	    void *state;
	} clean;
    } log;
#if !HEAP_REPLACEMENT
    dlink_list lru_list;
    dlink_node *lru_walker;
#endif
    union {
	struct {
	    int l1;
	    int l2;
	    int swaplog_fd;
	} ufs;
#if USE_DISKD
	struct {
	    int l1;
	    int l2;
	    int swaplog_fd;
	    int smsgid;
	    int rmsgid;
	    int wfd;
	    int away;
	    struct {
		char *buf;
		link_list *stack;
		int id;
	    } shm;
	} diskd;
#endif
    } u;
};

struct _request_flags {
    unsigned int range:1;
    unsigned int nocache:1;
    unsigned int ims:1;
    unsigned int auth:1;
    unsigned int cachable:1;
    unsigned int hierarchical:1;
    unsigned int loopdetect:1;
    unsigned int proxy_keepalive:1;
    unsigned int proxying:1;
    unsigned int refresh:1;
    unsigned int used_proxy_auth:1;
    unsigned int redirected:1;
    unsigned int need_validation:1;
#if HTTP_VIOLATIONS
    unsigned int nocache_hack:1;	/* for changing/ignoring no-cache requests */
#endif
    unsigned int accelerated:1;
    unsigned int internal:1;
};

struct _link_list {
    void *ptr;
    struct _link_list *next;
};

struct _storeIOState {
    sfileno swap_file_number;
    mode_t mode;
    size_t st_size;		/* do stat(2) after read open */
    off_t offset;		/* current offset pointer */
    STIOCB *callback;
    void *callback_data;
    struct {
	STRCB *callback;
	void *callback_data;
    } read;
    struct {
	unsigned int closing:1;	/* debugging aid */
    } flags;
    union {
	struct {
	    int fd;
	    struct {
		unsigned int close_request:1;
		unsigned int reading:1;
		unsigned int writing:1;
	    } flags;
	} ufs;
	struct {
	    int fd;
	    struct {
		unsigned int close_request:1;
		unsigned int reading:1;
		unsigned int writing:1;
		unsigned int opening:1;
	    } flags;
	    const char *read_buf;
	    link_list *pending_writes;
	    link_list *pending_reads;
	} aufs;
#if USE_DISKD
	struct {
	    int id;
	    struct {
		unsigned int reading:1;
		unsigned int writing:1;
	    } flags;
	    char *read_buf;
	} diskd;
#endif
    } type;
};

struct _request_t {
    method_t method;
    protocol_t protocol;
    char login[MAX_LOGIN_SZ];
    char host[SQUIDHOSTNAMELEN + 1];
    char user_ident[USER_IDENT_SZ];	/* from proxy auth or ident server */
    u_short port;
    String urlpath;
    char *canonical;
    int link_count;		/* free when zero */
    request_flags flags;
    HttpHdrCc *cache_control;
    HttpHdrRange *range;
    float http_ver;
    time_t ims;
    int imslen;
    int max_forwards;
    /* these in_addr's could probably be sockaddr_in's */
    struct in_addr client_addr;
    struct in_addr my_addr;
    unsigned short my_port;
    HttpHeader header;
    char *body;
    size_t body_sz;
    int content_length;
    HierarchyLogEntry hier;
    err_type err_type;
    char *peer_login;		/* Configured peer login:password */
    time_t lastmod;		/* Used on refreshes */
};

struct _cachemgr_passwd {
    char *passwd;
    wordlist *actions;
    cachemgr_passwd *next;
};

struct _refresh_t {
    char *pattern;
    regex_t compiled_pattern;
    time_t min;
    double pct;
    time_t max;
    refresh_t *next;
    struct {
	unsigned int icase:1;
#if HTTP_VIOLATIONS
	unsigned int override_expire:1;
	unsigned int override_lastmod:1;
	unsigned int reload_into_ims:1;
	unsigned int ignore_reload:1;
#endif
    } flags;
};

struct _CommWriteStateData {
    char *buf;
    size_t size;
    off_t offset;
    CWCB *handler;
    void *handler_data;
    FREE *free_func;
};

struct _ErrorState {
    err_type type;
    int page_id;
    http_status http_status;
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
    struct {
	unsigned int flag_cbdata:1;
    } flags;
    struct {
	wordlist *server_msg;
	char *request;
	char *reply;
    } ftp;
    char *request_hdrs;
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
    int select_loops;
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
#if HAVE_POLL
	int polls;
#else
	int selects;
#endif
    } syscalls;
    int swap_files_cleaned;
    int aborted_requests;
};

/* per header statistics */
struct _HttpHeaderStat {
    const char *label;
    HttpHeaderMask *owner_mask;

    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;

    int parsedCount;
    int ccParsedCount;
    int destroyedCount;
    int busyDestroyedCount;
};


struct _tlv {
    char type;
    int length;
    void *value;
    tlv *next;
};

struct _storeSwapLogData {
    char op;
    sfileno swap_file_number;
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    size_t swap_file_sz;
    u_short refcount;
    u_short flags;
    unsigned char key[MD5_DIGEST_CHARS];
};

/* object to track per-action memory usage (e.g. #idle objects) */
struct _MemMeter {
    ssize_t level;		/* current level (count or volume) */
    ssize_t hwater_level;	/* high water mark */
    time_t hwater_stamp;	/* timestamp of last high water mark change */
};

/* object to track per-pool memory usage (alloc = inuse+idle) */
struct _MemPoolMeter {
    MemMeter alloc;
    MemMeter inuse;
    MemMeter idle;
    gb_t saved;
    gb_t total;
};

/* a pool is a [growing] space for objects of the same size */
struct _MemPool {
    const char *label;
    size_t obj_size;
    Stack pstack;		/* stack for free pointers */
    MemPoolMeter meter;
};

struct _ClientInfo {
    /* first two items must be equivalent to hash_link */
    char *key;
    ClientInfo *next;
    struct in_addr addr;
    struct {
	int result_hist[LOG_TYPE_MAX];
	int n_requests;
	kb_t kbytes_in;
	kb_t kbytes_out;
	kb_t hit_kbytes_out;
    } Http, Icp;
    struct {
	time_t time;
	int n_req;
	int n_denied;
    } cutoff;
    int n_established;		/* number of current established connections */
};

struct _CacheDigest {
    /* public, read-only */
    char *mask;			/* bit mask */
    size_t mask_size;		/* mask size in bytes */
    int capacity;		/* expected maximum for .count, not a hard limit */
    int bits_per_entry;		/* number of bits allocated for each entry from capacity */
    int count;			/* number of digested entries */
    int del_count;		/* number of deletions performed so far */
};

struct _FwdServer {
    peer *peer;			/* NULL --> origin server */
    hier_code code;
    FwdServer *next;
};

struct _FwdState {
    int client_fd;
    StoreEntry *entry;
    request_t *request;
    FwdServer *servers;
    int server_fd;
    ErrorState *err;
    time_t start;
    int n_tries;
    struct {
	unsigned int dont_retry:1;
	unsigned int ftp_pasv_failed:1;
    } flags;
};

#if USE_HTCP
struct _htcpReplyData {
    int hit;
    HttpHeader hdr;
    u_num32 msg_id;
    double version;
    struct {
	/* cache-to-origin */
	double rtt;
	int samp;
	int hops;
    } cto;
};

#endif


struct _helper_request {
    char *buf;
    HLPCB *callback;
    void *data;
};

struct _helper {
    wordlist *cmdline;
    dlink_list servers;
    dlink_list queue;
    const char *id_name;
    int n_to_start;
    int n_running;
    int ipc_type;
    time_t last_queue_warn;
    struct {
	int requests;
	int replies;
	int queue_size;
	int avg_svc_time;
    } stats;
};

struct _helper_server {
    int index;
    int rfd;
    int wfd;
    char *buf;
    size_t buf_sz;
    off_t offset;
    struct timeval dispatch_time;
    struct timeval answer_time;
    dlink_node link;
    helper *parent;
    helper_request *request;
    struct _helper_flags {
	unsigned int alive:1;
	unsigned int busy:1;
	unsigned int closing:1;
	unsigned int shutdown:1;
    } flags;
    struct {
	int uses;
    } stats;
};

/*
 * use this when you need to pass callback data to a blocking
 * operation, but you don't want to add that pointer to cbdata
 */
struct _generic_cbdata {
    void *data;
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
