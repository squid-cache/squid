


struct _acl_ip_data {
    struct in_addr addr1;	/* if addr2 non-zero then its a range */
    struct in_addr addr2;
    struct in_addr mask;
    acl_ip_data *next;
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

struct _acl_proxy_auth {
    char *filename;
    time_t last_time;
    time_t change_time;
    int check_interval;
    hash_table *hash;
};

struct _acl_proxy_auth_user {
    /* first two items must be same as hash_link */
    char *user;
    acl_proxy_auth_user *next;
    char *passwd;
};

struct _acl_deny_info_list {
    int err_page_id;
    char *err_page_name;
    acl_name_list *acl_list;
    acl_deny_info_list *next;
};

#if USE_ARP_ACL
struct _acl_arp_data {
    unsigned char eth[6];
#ifndef USE_SPLAY_TREE
    acl_arp_data *next;
#endif
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

struct _viewEntry {
    char viewName[32];
    int viewIndex;
    int viewType;
    int viewSubtreeLen;
    oid viewSubtree[32];
    struct _viewEntry *next;
};

struct _communityEntry {
    char name[64];
    int readView;
    int writeView;
    acl_access *acls;
    communityEntry *next;
};

struct _usecEntry {
    u_char userName[32];
    int userLen;
    int qoS;
    u_char authKey[16];
    u_char privKey[16];
    int noauthReadView;
    int noauthWriteView;
    int authReadView;
    int authWriteView;
    usecEntry *next;
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
    request_t *request;
    char ident[ICP_IDENT_SZ];
    char browser[BROWSERNAMELEN];
    acl_lookup_state state[ACL_ENUM_MAX];
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

struct _ushortlist {
    u_short i;
    ushortlist *next;
};

struct _relist {
    char *pattern;
    regex_t regex;
    relist *next;
};

struct _SquidConfig {
    struct {
	size_t maxSize;
	int highWaterMark;
	int lowWaterMark;
    } Mem , Swap;
    struct {
	char *relayHost;
	u_short relayPort;
    } Wais;
    struct {
	size_t min;
	int pct;
	size_t max;
    } quickAbort;
    time_t referenceAge;
    time_t negativeTtl;
    time_t negativeDnsTtl;
    time_t positiveDnsTtl;
    time_t shutdownLifetime;
    time_t neighborTimeout;
    struct {
	time_t read;
	time_t lifetime;
	time_t connect;
	time_t request;
	time_t pconn;
	time_t siteSelect;
	time_t deadPeer;
    } Timeout;
    size_t maxRequestSize;
    struct {
	ushortlist *http;
	u_short icp;
#if USE_HTCP
	u_short htcp;
#endif
#if SQUID_SNMP
	u_short snmp;
#endif
    } Port;
#if SQUID_SNMP
    struct {
	char *configFile;
	char *agentInfo;
	char *mibPath;
	char *trap_community;
	char *trap_sink;
	u_short localPort;
	int do_queueing;
	int conf_authtraps;
	wordlist *snmpconf;
	viewEntry *views;
	usecEntry *users;
	communityEntry *communities;
    } Snmp;
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
	char *redirect;
	char *pinger;
	char *unlinkd;
    } Program;
    int dnsChildren;
    int redirectChildren;
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
    char *errHtmlText;
    struct {
	char *host;
	char *file;
	time_t period;
	u_short port;
    } Announce;
    struct {
	struct in_addr tcp_incoming;
	struct in_addr tcp_outgoing;
	struct in_addr udp_incoming;
	struct in_addr udp_outgoing;
	struct in_addr snmp_incoming;
	struct in_addr snmp_outgoing;
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
	int enable_purge;
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
	int ident_lookup;
	int log_fqdn;
	int announce;
	int accel_with_proxy;
	int mem_pools;
	int test_reachability;
	int half_closed_clients;
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
    } accessList;
    acl_deny_info_list *denyInfoList;
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
};

struct _SquidConfig2 {
    struct {
	char *prefix;
	int on;
    } Accel;
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
    int flags;
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

struct _fde {
    unsigned int type;
    unsigned int open;
    u_short local_port;
    u_short remote_port;
    char ipaddr[16];		/* dotted decimal address of peer */
    char desc[FD_DESC_SZ];
    struct {
	int close_request:1;
	int write_daemon:1;
	int closing:1;
	int socket_eof:1;
	int nolinger:1;
	int nonblocking:1;
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

struct _hash_link {
    char *key;
    hash_link *next;
};

struct _hash_table {
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *next;
    int count;
};

/* http status line */
struct _HttpStatusLine {
    /* public, read only */
    float version;
    const char *reason;		/* points to a _constant_ string (default or supplied), never free()d */
    http_status status;
};

/*
 * Note: HttpBody is used only for messages with a small text content that is
 * known a priory (e.g., error messages).
 */
struct _HttpBody {
    /* private, never dereference these */
    char *buf;			/* null terminated _text_ buffer, not for binary stuff */
    FREE *freefunc;		/* used to free() .buf */
    int size;
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
};

/* http byte-range-spec */
struct _HttpHdrRangeSpec {
    size_t offset;
    size_t length;
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
    size_t elength;		/* entity length, not content length */
};


/* per field statistics */
struct _HttpHeaderFieldStat {
    int aliveCount;		/* created but not destroyed (count) */
    int seenCount;		/* #fields we've seen */
    int parsCount;		/* #parsing attempts */
    int errCount;		/* #pasring errors */
    int repCount;		/* #repetitons */
};

/* constant attributes of http header fields */
struct _HttpHeaderFieldAttrs {
    const char *name;
    http_hdr_type id;
    field_type type;
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
    http_hdr_owner_type owner;  /* request or reply */
    int len;                    /* length when packed, not counting terminating '\0' */
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


struct _HttpStateData {
    StoreEntry *entry;
    request_t *request;
    char *reply_hdr;
    int reply_hdr_state;
    peer *peer;			/* peer request made to */
    int eof;			/* reached end-of-object? */
    request_t *orig_request;
    int fd;
    int flags;
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

struct _icp_ping_data {
    struct timeval start;
    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;
    int w_rtt;
    int p_rtt;
};

struct _HierarchyLogEntry {
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    icp_ping_data icp;
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
	char *buf;
	off_t offset;
	size_t size;
    } out;
    size_t req_sz;              /* raw request size on input, not current request size */
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
	int accel:1;
	int internal:1;
    } flags;
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
    struct {
	int fd;
	char ident[ICP_IDENT_SZ];
	IDCB *callback;
	int state;
	void *callback_data;
    } ident;
    CommWriteStateData *commWriteState;
    int nrequests;
    int persistent;
    struct {
	int n;
	time_t until;
    } defer;
};

struct _dlink_node {
    void *data;
    dlink_node *prev;
    dlink_node *next;
};

struct _dlink_list {
    dlink_node *head;
    dlink_node *tail;
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
    peer *peer;
    StoreEntry *entry;
    StoreEntry *old_entry;
    int offset;
    int mask_offset;
    time_t start_time;
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
    CacheDigest *cd;
    int flags;			/* PD_ */
    time_t last_fetch_resp_time;
    time_t last_req_timestamp;
    time_t last_dis_delay;	/* last disability delay */
    struct {
	cd_guess_stats guess;
	int used_count;
	int msgs_sent;
	int msgs_recv;
	kb_t kbytes_sent;
	kb_t kbytes_recv;
    } stats;
};

struct _peer {
    char *host;
    peer_t type;
    struct sockaddr_in in_addr;
    struct {
	int pings_sent;
	int pings_acked;
	int fetches;
	int rtt;
	int counts[ICP_END];
	int ignored_replies;
	int n_keepalives_sent;
	int n_keepalives_recv;
	time_t last_query;
	time_t last_reply;
	int logged_state;	/* so we can print dead/revived msgs */
    } stats;
    u_short icp_port;
    u_short http_port;
    int icp_version;
    domain_ping *pinglist;
    domain_type *typelist;
    acl_list *acls;
    int options;
    int weight;
    struct {
	double avg_n_members;
	int n_times_counted;
	int n_replies_expected;
	int ttl;
	u_num32 reqnum;
	int flags;
    } mcast;
    PeerDigest digest;
    int tcp_up;			/* 0 if a connect() fails */
    time_t last_fail_time;
    struct in_addr addresses[10];
    int n_addresses;
    int rr_count;
    peer *next;
    int test_fd;
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
    PSC *callback;
    PSC *fail_callback;
    void *callback_data;
    peer *first_parent_miss;
    peer *closest_parent_miss;
    peer *single_parent;
    icp_ping_data icp;
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

/* auto-growing memory-resident buffer with printf interface */
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
    int swapin_fd;
    struct {
	int disk_io_pending:1;
	int store_copying:1;
	int copy_event_pending:1;
    } flags;
    store_client *next;
};


/* This structure can be freed while object is purged out from memory */
struct _MemObject {
    method_t method;
    char *url;
    mem_hdr *data;
    off_t inmem_hi;
    off_t inmem_lo;
    store_client *clients;
    int nclients;
    struct {
	off_t queue_offset;	/* relative to in-mem data */
	off_t done_offset;	/* relative to swap file with meta headers! */
	int fd;
	void *ctrl;
    } swapout;
    HttpReply *reply;
    request_t *request;
    struct timeval start_ping;
    IRCB *icp_reply_callback;
    void *ircb_data;
    int fd;			/* FD of client creating this entry */
    struct {
	STABH *callback;
	void *data;
    } abort;
    char *log_url;
    dlink_node lru;
    u_num32 reqnum;
    ssize_t object_sz;
    size_t swap_hdr_sz;
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
    u_short flag;

    int swap_file_number;
    dlink_node lru;
    u_char lock_count;		/* Assume < 256! */
    mem_status_t mem_status:3;
    ping_status_t ping_status:3;
    store_status_t store_status:3;
    swap_status_t swap_status:3;
};

struct _SwapDir {
    char *path;
    int l1;
    int l2;
    int cur_size;
    int max_size;
    int read_only;
    int suggest;
    fileMap *map;
    int swaplog_fd;
};

struct _request_t {
    method_t method;
    protocol_t protocol;
    char login[MAX_LOGIN_SZ];
    char host[SQUIDHOSTNAMELEN + 1];
    u_short port;
    String urlpath;
    int link_count;		/* free when zero */
    int flags;
    HttpHdrCc *cache_control;
    time_t max_age;
    float http_ver;
    time_t ims;
    int imslen;
    int max_forwards;
    struct in_addr client_addr;
#if OLD_CODE
    char *headers;
    size_t headers_sz;
#else
    HttpHeader header;
#endif
    char *body;
    size_t body_sz;
    HierarchyLogEntry hier;
    err_type err_type;
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
	int icase:1;
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
    int flags;
    struct {
	char *request;
	char *reply;
    } ftp;
    char *request_hdrs;
    wordlist *ftp_server_msg;
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
    hbase_f val_in;		/* e.g., log() for log-based histogram */
    hbase_f val_out;		/* e.g., exp() for log based histogram */
};

/*
 * if you add a field to StatCounters, 
 * you MUST sync statCountersInitSpecial, statCountersClean, and statCountersCopy
 */
struct _StatCounters {
    struct {
	int requests;
	int hits;
	int errors;
	kb_t kbytes_in;
	kb_t kbytes_out;
	kb_t hit_kbytes_out;
	StatHist miss_svc_time;
	StatHist nm_svc_time;
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
	cd_guess_stats guess;
	StatHist on_xition_count;
    } cd;
    struct {
	int times_used;
    } netdb;
    int page_faults;
    int select_loops;
    double cputime;
    struct timeval timestamp;
    StatHist comm_incoming;
};

struct _tlv {
    char type;
    int length;
    void *value;
    tlv *next;
};

struct _storeSwapLogData {
    char op;
    int swap_file_number;
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
    size_t level;		/* current level (count or volume) */
    size_t hwater_level;	/* high water mark */
    time_t hwater_stamp;	/* timestamp of last high water mark change */
};

/* object to track per-pool memory usage (alloc = inuse+idle) */
struct _MemPoolMeter {
    MemMeter alloc;
    MemMeter inuse;
    MemMeter idle;
    gb_t saved;
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
