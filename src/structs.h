
struct _acl_ip_data {
    struct in_addr addr1;	/* if addr2 non-zero then its a range */
    struct in_addr addr2;
    struct in_addr mask;
#ifndef USE_SPLAY_TREE
    struct _acl_ip_data *next;
#endif
};

struct _acl_time_data {
    int weekbits;
    int start;
    int stop;
    struct _acl_time_data *next;
};

struct _acl_name_list {
    char name[ACL_NAME_SZ];
    struct _acl_name_list *next;
};

struct _acl_deny_info_list {
    char url[MAX_URL];
    struct _acl_name_list *acl_list;
    struct _acl_deny_info_list *next;
};

struct _acl {
    char name[ACL_NAME_SZ];
    squid_acl type;
    void *data;
    char *cfgline;
    struct _acl *next;
};

struct _acl_list {
    int op;
    struct _acl *acl;
    struct _acl_list *next;
};

struct _acl_access {
    int allow;
    struct _acl_list *acl_list;
    char *cfgline;
    struct _acl_access *next;
};

struct _aclCheck_t {
    const struct _acl_access *access_list;
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
    struct _wordlist *next;
};

struct _intlist {
    int i;
    struct _intlist *next;
};

struct _ushortlist {
    u_short i;
    struct _ushortlist *next;
};

struct _relist {
    char *pattern;
    regex_t regex;
    struct _relist *next;
};

struct _cache_peer {
    char *host;
    char *type;
    u_short http;
    u_short icp;
    int options;
    int weight;
    int mcast_ttl;
    domain_ping *pinglist;
    domain_type *typelist;
    acl_list *acls;
    struct _cache_peer *next;
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
    time_t stallDelay;
    struct {
	time_t read;
	time_t defer;
	time_t lifetime;
	time_t connect;
	time_t request;
    } Timeout;
    size_t maxRequestSize;
    struct {
	ushortlist *http;
	u_short icp;
    } Port;
    struct {
	char *log;
	char *access;
	char *store;
	char *swap;
	char *useragent;
	int rotateNumber;
	int log_fqdn;
    } Log;
    struct {
	char *File;
	relist *IgnoreDomains;
    } proxyAuth;
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
    int sourcePing;
    int commonLogFormat;
    int logMimeHdrs;
    int identLookup;
    int singleParentBypass;
    struct {
	char *host;
	u_short port;
	int withProxy;
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
	int on;
	u_short port;
    } Announce;
    struct {
	struct in_addr tcp_incoming;
	struct in_addr tcp_outgoing;
	struct in_addr udp_incoming;
	struct in_addr udp_outgoing;
	struct in_addr client_netmask;
    } Addrs;
    size_t tcpRcvBufsz;
    size_t udpMaxHitObjsz;
    wordlist *cache_stoplist;
    wordlist *hierarchy_stoplist;
    wordlist *mcast_group_list;
    wordlist *dns_testname_list;
    relist *cache_stop_relist;
    cache_peer *peers;
    cache_peer *sslProxy;
    cache_peer *passProxy;
    struct {
	size_t size;
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
    } Options;
    struct _acl *aclList;
    struct {
	struct _acl_access *http;
	struct _acl_access *icp;
	struct _acl_access *miss;
	struct _acl_access *NeverDirect;
	struct _acl_access *AlwaysDirect;
    } accessList;
    struct _acl_deny_info_list *denyInfoList;
    struct {
	size_t list_width;
	int list_wrap;
	char *icon_prefix;
	char *icon_suffix;
	char *anon_user;
    } Ftp;
    refresh_t *Refresh;
    struct _cacheSwap {
        SwapDir *swapDirs;
        int n_allocated;
        int n_configured;
    } cacheSwap;
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
    unsigned int offset;
    unsigned int size;
    char *ip_inbuf;
    struct timeval dispatch_time;
    void *data;
};

struct _dnsStatData {
    int requests;
    int replies;
    int hist[DefaultDnsChildrenMax];
};

struct _dwrite_q {
    char *buf;
    int len;
    int cur_offset;
    struct _dwrite_q *next;
    void (*free) (void *);
};


struct _fde {
    unsigned int type;
    unsigned int open;
    u_short local_port;
    u_short remote_port;
    char ipaddr[16];		/* dotted decimal address of peer */
    char desc[FD_DESC_SZ];
    int flags;
    int bytes_read;
    int bytes_written;
    struct _fde_disk {
	DWCB *wrt_handle;
	void *wrt_handle_data;
	dwrite_q *write_q;
	dwrite_q *write_q_tail;
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
    time_t stall_until;		/* don't select for read until this time */
    CommWriteStateData *rwstate;	/* State data for comm_write */
};

struct _fileMap {
    int max_n_files;
    int n_files_in_map;
    int last_file_number_allocated;
    int toggle;
    int nwords;
    unsigned long *file_map;
};

struct _fqdncache_entry {
    /* first two items must be equivalent to hash_link in hash.h */
    char *name;
    struct _fqdncache_entry *next;
    time_t lastref;
    time_t expires;
    unsigned char name_count;
    char *names[FQDN_MAX_NAMES + 1];
    struct _fqdn_pending *pending_head;
    char *error_message;
    unsigned char locks;
    fqdncache_status_t status:3;
};

struct _hash_link {
    char *key;
    struct _hash_link *next;
    void *item;
};

struct _hash_table {
    int valid;
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *current_ptr;
};

struct _http_reply {
    double version;
    int code;
    int content_length;
    int hdr_sz;
    int cache_control;
    int misc_headers;
    time_t date;
    time_t expires;
    time_t last_modified;
    char content_type[HTTP_REPLY_FIELD_SZ];
    char user_agent[HTTP_REPLY_FIELD_SZ << 2];
};

struct _HttpStateData {
    StoreEntry *entry;
    request_t *request;
    char *reply_hdr;
    int reply_hdr_state;
    peer *neighbor;		/* neighbor request made to */
    int eof;			/* reached end-of-object? */
    request_t *orig_request;
    int fd;			/* needed as identifier for ipcache */
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
    protocol_t proto;
};

struct _icp_ping_data {
    struct timeval start;
    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;
    int w_rtt;
};

struct _HierarchyLogEntry {
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    struct _icp_ping_data icp;
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
    struct _HierarchyLogEntry hier;
    struct {
	char *request;
	char *reply;
    } headers;
    struct {
	const char *method_str;
    } private;
};

struct _clientHttpRequest {
    ConnStateData *conn;
    request_t *request;		/* Parsed URL ... */
    char *url;
    struct {
	char *buf;
	int offset;
	int size;
    } out;
    size_t req_sz;
    StoreEntry *entry;
    StoreEntry *old_entry;
    log_type log_type;
    int http_code;
    int accel;
    struct timeval start;
    float http_ver;
    int redirect_state;
    aclCheck_t *acl_checklist;	/* need ptr back so we can unreg if needed */
    clientHttpRequest *next;
    struct _AccessLogEntry al;
};

struct _ConnStateData {
    int fd;
    struct {
	char *buf;
	int offset;
	int size;
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
    } ident;
    CommWriteStateData *commWriteState;
    int nrequests;
    int persistent;
};

struct _ipcache_addrs {
    unsigned char count;
    unsigned char cur;
    struct in_addr *in_addrs;
};

struct _ipcache_entry {
    /* first two items must be equivalent to hash_link in hash.h */
    char *name;
    struct _ipcache_entry *next;
    time_t lastref;
    time_t expires;
    ipcache_addrs addrs;
    struct _ip_pending *pending_head;
    char *error_message;
    unsigned char locks;
    ipcache_status_t status:3;
};

struct _ext_table_entry {
    char *name;
    char *mime_type;
    char *mime_encoding;
    char *icon;
};

struct _domain_ping {
    char *domain;
    int do_ping;		/* boolean */
    struct _domain_ping *next;
};

struct _domain_type {
    char *domain;
    peer_t type;
    struct _domain_type *next;
};

struct _peer {
    char *host;
    peer_t type;
    struct sockaddr_in in_addr;
    struct {
	int pings_sent;
	int pings_acked;
	int ack_deficit;
	int fetches;
	int rtt;
	int counts[ICP_OP_END];
	int ignored_replies;
    } stats;
    u_short icp_port;
    u_short http_port;
    int icp_version;
    struct _domain_ping *pinglist;
    struct _domain_type *typelist;
    struct _acl_list *acls;
    int options;
    int weight;
    struct {
	double avg_n_members;
	int n_times_counted;
	int n_replies_expected;
	int ttl;
	int reqnum;
	int flags;
    } mcast;
    int tcp_up;			/* 0 if a connect() fails */
    time_t last_fail_time;
    struct in_addr addresses[10];
    int n_addresses;
    int rr_count;
    struct _peer *next;
    int ip_lookup_pending;
    int test_fd;
};

struct _net_db_name {
    char *name;
    struct _net_db_name *next;
};

struct _net_db_peer {
    char *peername;
    double hops;
    double rtt;
    time_t expires;
};

struct _netdbEntry {
    char *key;
    struct _net_db *next;
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
    icp_ping_data icp;
    aclCheck_t *acl_checklist;
};

struct _pingerEchoData {
    struct in_addr to;
    unsigned char opcode;
    int psize;
    char payload[8192];
};

struct _pingerReplyData {
    struct in_addr from;
    unsigned char opcode;
    int rtt;
    int hops;
    int psize;
    char payload[8192];
};

struct _icp_common_t {
    unsigned char opcode;	/* opcode */
    unsigned char version;	/* version number */
    unsigned short length;	/* total length (bytes) */
    u_num32 reqnum;		/* req number (req'd for UDP) */
    u_num32 flags;
    u_num32 pad;
    /* u_num32 auth[ICP_AUTH_SIZE];     authenticator (old) */
    u_num32 shostid;		/* sender host id */
};

struct _Stack {
    void **base;
    void **top;
    int stack_size;
};

struct _proto_stat {
    char protoname[25];
    int object_count;
    struct _usage {
	int max;
	int avg;
	int min;
	int now;
    } kb;
    unsigned int hit;
    unsigned int miss;
    float hitratio;
    unsigned int transferrate;
    unsigned int refcount;
    unsigned int transferbyte;
};

struct _Meta_data {
    int hot_vm;
    int store_entries;
    int mem_obj_count;
    int mem_data_count;
    int ipcache_count;
    int fqdncache_count;
    int netdb_addrs;
    int netdb_hosts;
    int netdb_peers;
    int url_strings;
    int misc;
    int client_info;
};

struct _cacheinfo {
    protocol_t(*proto_id) (const char *url);
    void (*proto_newobject) (struct _cacheinfo * c, protocol_t proto_id, int len, int flag);
    void (*proto_purgeobject) (struct _cacheinfo * c, protocol_t proto_id, int len);
    void (*proto_touchobject) (struct _cacheinfo * c, protocol_t proto_id, int len);
    void (*proto_count) (struct _cacheinfo * obj, protocol_t proto_id,
	log_type);
    proto_stat proto_stat_data[PROTO_MAX + 1];
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

/* Memory allocator routines for fixed size blocks */
struct _stmem_stats {
    int max_pages;
    int total_pages_allocated;
    int page_size;
    int n_pages_in_use;
    Stack free_page_stack;
};

/* keep track each client receiving data from that particular StoreEntry */
struct _store_client {
    off_t copy_offset;
    off_t seen_offset;
    size_t copy_size;
    char *copy_buf;
    STCB *callback;
    void *callback_data;
};


/* This structure can be freed while object is purged out from memory */
struct _MemObject {
    mem_hdr *data;
    char *e_swap_buf;
    int w_rtt;			/* weighted RTT in msec */
    peer *e_pings_closest_parent;	/* parent with best RTT to source */
    int p_rtt;			/* parent's RTT to source */
    int e_swap_buf_len;
    unsigned char pending_list_size;
    char *e_abort_msg;
    log_type abort_code;
    int e_current_len;
    int e_lowest_offset;
    struct _store_client *clients;
    int nclients;
    u_num32 swap_offset;
    short swapin_fd;
    short swapout_fd;
    struct _http_reply *reply;
    request_t *request;
    struct timeval start_ping;
    IRCB *icp_reply_callback;
    void *ircb_data;
    int fd;			/* FD of client creating this entry */
    struct {
	STABH *callback;
	void *data;
    } abort;
};

/* A cut down structure for store manager */
struct _StoreEntry {
    /* first two items must be same as hash_link in hash.h */
    char *key;
    struct sentry *next;
    char *url;
    MemObject *mem_obj;
    u_num32 flag;
    u_num32 refcount;
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    int object_len;
    int swap_file_number;
    mem_status_t mem_status:3;
    ping_status_t ping_status:3;
    store_status_t store_status:3;
    swap_status_t swap_status:3;
    method_t method:4;
    unsigned char lock_count;	/* Assume < 256! */
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
    char urlpath[MAX_URL];
    int link_count;		/* free when zero */
    int flags;
    time_t max_age;
    float http_ver;
    time_t ims;
    int imslen;
    int max_forwards;
    struct in_addr client_addr;
    char *headers;
    size_t headers_sz;
    char *body;
    size_t body_sz;
    struct _HierarchyLogEntry hier;
};

struct _cachemgr_passwd {
    char *passwd;
    long actions;
    struct _cachemgr_passwd *next;
};

struct _refresh_t {
    char *pattern;
    regex_t compiled_pattern;
    time_t min;
    int pct;
    time_t max;
    struct _refresh_t *next;
};

struct _CommWriteStateData {
    char *buf;
    size_t size;
    off_t offset;
    CWCB *handler;
    void *handler_data;
    FREE *free;
};
