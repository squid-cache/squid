


struct _acl_ip_data {
    struct in_addr addr1;	/* if addr2 non-zero then its a range */
    struct in_addr addr2;
    struct in_addr mask;
#ifndef USE_SPLAY_TREE
    acl_ip_data *next;
#endif
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

struct _acl_deny_info_list {
    char url[MAX_URL];
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

#if SQUID_SNMP
struct _snmpconf {
    char *line;
    int type;
    snmpconf *next;
};

struct _snmp_request_t {
	char *buf;
	char *outbuf;
	int len;
	int sock;
        long reqid;
	int outlen;
	struct sockaddr_in from;
	struct snmp_pdu *PDU;
	aclCheck_t *acl_checklist;
        char *community;
};

typedef struct _viewEntry {
    char viewName[32];
    int viewIndex;
    int viewType;
    int viewSubtreeLen;
    oid viewSubtree[32];
    struct _viewEntry *next;
} viewEntry;

typedef struct _communityEntry {
    char name[64];
    int readView;
    int writeView;
    struct _acl_access *acls;
    struct _communityEntry *next;
} communityEntry;

typedef struct _usecEntry {
    u_char userName[32];
    int userLen;
    int qoS;
    u_char authKey[16];
    u_char privKey[16];
    int noauthReadView;
    int noauthWriteView;
    int authReadView;
    int authWriteView;
    struct _usecEntry *next;
} usecEntry;

#endif

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
	struct _snmpconf *snmpconf;
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
    wordlist *cache_stoplist;
    wordlist *hierarchy_stoplist;
    wordlist *mcast_group_list;
    wordlist *dns_testname_list;
    wordlist *dns_nameservers;
    relist *cache_stop_relist;
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
	int source_ping;
	int common_log;
	int log_mime_hdrs;
	int ident_lookup;
	int single_parent_bypass;
	int log_fqdn;
	int announce;
	int accel_with_proxy;
	int mem_pools;
    } onoff;
    struct _acl *aclList;
    struct {
	struct _acl_access *http;
	struct _acl_access *icp;
	struct _acl_access *miss;
	struct _acl_access *NeverDirect;
	struct _acl_access *AlwaysDirect;
	struct _acl_access *ASlists;
    } accessList;
    struct _acl_deny_info_list *denyInfoList;
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
    struct _dwrite_q *next;
    FREE *free_func;
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
    time_t connect_timeout;
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

#include "MemBuf.h"
#include "Packer.h"
#include "HttpReply.h"

#if 0				/* tmp moved to HttpReply.h */
#define Const const
struct _http_reply {
    double version;
    int code;
    int content_length;
    int hdr_sz;			/* includes _stored_ status-line, headers, and <CRLF> */
    /* Note: fields below may not match info stored on disk */
    Const int cache_control;
    Const int misc_headers;
    Const time_t date;
    Const time_t expires;
    Const time_t last_modified;
    Const char content_type[HTTP_REPLY_FIELD_SZ];
#if 0				/* unused 512 bytes? */
    Const char user_agent[HTTP_REPLY_FIELD_SZ << 2];
#endif
};

#endif


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
    int p_rtt;
};

struct _HierarchyLogEntry {
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    icp_ping_data icp;
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
    char *uri;
    char *log_uri;
    struct {
	char *buf;
	off_t offset;
	size_t size;
    } out;
    size_t req_sz;
    StoreEntry *entry;
    StoreEntry *old_entry;
    log_type log_type;
    http_status http_code;
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

struct _ipcache_entry {
    /* first two items must be equivalent to hash_link in hash.h */
    char *name;
    struct _ipcache_entry *next;
    time_t lastref;
    time_t expires;
    ipcache_addrs addrs;
    struct _ip_pending *pending_head;
    char *error_message;
    dlink_node lru;
    u_char locks;
    ipcache_status_t status:3;
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
    dlink_node lru;
    unsigned char locks;
    fqdncache_status_t status:3;
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
	u_num32 reqnum;
	int flags;
    } mcast;
    int tcp_up;			/* 0 if a connect() fails */
    time_t last_fail_time;
    struct in_addr addresses[10];
    int n_addresses;
    int rr_count;
    struct _peer *next;
    int ip_lookup_pending;
    int ck_conn_event_pend;
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
    u_num32 shostid;		/* sender host id */
};

#if 0				/* this struct is not used */
struct _Stack {
    void **base;
    void **top;
    int stack_size;
};

#endif

struct _Meta_data {
    int hot_vm;
    int ipcache_count;
    int fqdncache_count;
    int netdb_peers;
    int misc;
    int client_info;
    int store_keys;
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
    int swapin_fd;
    int disk_op_in_progress;
    struct _store_client *next;
};

/* This structure can be freed while object is purged out from memory */
struct _MemObject {
    method_t method;
    char *url;
    mem_hdr *data;
    off_t inmem_hi;
    off_t inmem_lo;
    struct _store_client *clients;
    int nclients;
    struct {
	off_t queue_offset;	/* relative to in-mem data */
	off_t done_offset;	/* relative to swap file with meta headers! */
	int fd;
	void *ctrl;
    } swapout;
#if 0
    struct _http_reply *reply;
#else
    HttpReply *reply;
#endif
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
    /* first two items must be same as hash_link in hash.h */
    const cache_key *key;
    struct _StoreEntry *next;
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
    err_type err_type;
};

struct _cachemgr_passwd {
    char *passwd;
    wordlist *actions;
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
    FREE *free_func;
};

struct _ErrorState {
    err_type type;
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
    hbase_f val_in;   /* e.g., log() for log-based histogram */
    hbase_f val_out;  /* e.g., exp() for log based histogram */
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
	int requests;
	int errors;
	kb_t kbytes_in;
	kb_t kbytes_out;
    } server;
    struct {
	int pkts_sent;
	int pkts_recv;
	int hits_sent;
	int hits_recv;
	kb_t kbytes_sent;
	kb_t kbytes_recv;
	StatHist query_svc_time;
	StatHist reply_svc_time;
    } icp;
    struct {
	int requests;
    } unlink;
    struct {
	StatHist svc_time;
    } dns;
    int page_faults;
    int select_loops;
    double cputime;
    struct timeval timestamp;
};

struct _tlv {
    char type;
    int length;
    void *value;
    struct _tlv *next;
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
