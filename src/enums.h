

typedef enum {
    LOG_TAG_NONE,		/* 0 */
    LOG_TCP_HIT,		/* 1 */
    LOG_TCP_MISS,		/* 2 */
    LOG_TCP_REFRESH_HIT,	/* 3 */
    LOG_TCP_REFRESH_FAIL_HIT,	/* 4 */
    LOG_TCP_REFRESH_MISS,	/* 5 */
    LOG_TCP_CLIENT_REFRESH,	/* 6 */
    LOG_TCP_IMS_HIT,		/* 7 */
    LOG_TCP_IMS_MISS,		/* 8 */
    LOG_TCP_SWAPFAIL_MISS,	/* 9 */
    LOG_TCP_DENIED,		/* 10 */
    LOG_UDP_HIT,		/* 11 */
    LOG_UDP_HIT_OBJ,		/* 12 */
    LOG_UDP_MISS,		/* 13 */
    LOG_UDP_DENIED,		/* 14 */
    LOG_UDP_INVALID,		/* 15 */
    LOG_UDP_MISS_NOFETCH,	/* 16 */
    ERR_READ_TIMEOUT,		/* 17 */
    ERR_LIFETIME_EXP,		/* 18 */
    ERR_NO_CLIENTS_BIG_OBJ,	/* 19 */
    ERR_READ_ERROR,		/* 20 */
    ERR_WRITE_ERROR,		/* 21 */
    ERR_CLIENT_ABORT,		/* 22 */
    ERR_CONNECT_FAIL,		/* 23 */
    ERR_INVALID_REQ,		/* 24 */
    ERR_UNSUP_REQ,		/* 25 */
    ERR_INVALID_URL,		/* 26 */
    ERR_NO_FDS,			/* 27 */
    ERR_DNS_FAIL,		/* 28 */
    ERR_NOT_IMPLEMENTED,	/* 29 */
    ERR_CANNOT_FETCH,		/* 30 */
    ERR_NO_RELAY,		/* 31 */
    ERR_DISK_IO,		/* 32 */
    ERR_ZERO_SIZE_OBJECT,	/* 33 */
    ERR_FTP_DISABLED,		/* 34 */
    ERR_PROXY_DENIED		/* 35 */
} log_type;

typedef enum {
    ACL_NONE,
    ACL_SRC_IP,
    ACL_DST_IP,
    ACL_SRC_DOMAIN,
    ACL_DST_DOMAIN,
    ACL_TIME,
    ACL_URLPATH_REGEX,
    ACL_URL_REGEX,
    ACL_URL_PORT,
    ACL_USER,
    ACL_PROTO,
    ACL_METHOD,
    ACL_BROWSER,
    ACL_ENUM_MAX
} squid_acl;

typedef enum {
    ACL_LOOKUP_NONE,
    ACL_LOOKUP_NEEDED,
    ACL_LOOKUP_PENDING,
    ACL_LOOKUP_DONE
} acl_lookup_state;

typedef enum {
    IP_ALLOW,
    IP_DENY
} ip_access_type;

enum {
    FD_NONE,
    FD_LOG,
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_UNKNOWN
};

enum {
    FD_READ,
    FD_WRITE
};

enum {
    FD_CLOSE,
    FD_OPEN
};

enum {
    FQDN_CACHED,
    FQDN_NEGATIVE_CACHED,
    FQDN_PENDING,		/* waiting to be dispatched */
    FQDN_DISPATCHED		/* waiting for reply from dnsserver */
};
typedef unsigned int fqdncache_status_t;

enum {
    IP_CACHED,
    IP_NEGATIVE_CACHED,
    IP_PENDING,			/* waiting to be dispatched */
    IP_DISPATCHED		/* waiting for reply from dnsserver */
};
typedef unsigned int ipcache_status_t;

typedef enum {
    PEER_NONE,
    PEER_SIBLING,
    PEER_PARENT,
    PEER_MULTICAST
} peer_t;

typedef enum {
    MGR_NONE,
    MGR_CLIENT_LIST,
    MGR_CONFIG,
    MGR_CONFIG_FILE,
    MGR_DNSSERVERS,
    MGR_FILEDESCRIPTORS,
    MGR_FQDNCACHE,
    MGR_INFO,
    MGR_IO,
    MGR_IPCACHE,
    MGR_LOG_CLEAR,
    MGR_LOG_DISABLE,
    MGR_LOG_ENABLE,
    MGR_LOG_STATUS,
    MGR_LOG_VIEW,
    MGR_NETDB,
    MGR_OBJECTS,
    MGR_REDIRECTORS,
    MGR_REFRESH,
    MGR_REMOVE,
    MGR_REPLY_HDRS,
    MGR_SERVER_LIST,
    MGR_SHUTDOWN,
    MGR_UTILIZATION,
    MGR_VM_OBJECTS,
    MGR_STOREDIR,
    MGR_CBDATA,
    MGR_MAX
} objcache_op;

typedef enum {
    HIER_NONE,
    DIRECT,
    SIBLING_HIT,
    PARENT_HIT,
    DEFAULT_PARENT,
    SINGLE_PARENT,
    FIRSTUP_PARENT,
    NO_PARENT_DIRECT,
    FIRST_PARENT_MISS,
    CLOSEST_PARENT_MISS,
    CLOSEST_DIRECT,
    NO_DIRECT_FAIL,
    SOURCE_FASTEST,
    SIBLING_UDP_HIT_OBJ,
    PARENT_UDP_HIT_OBJ,
    PASS_PARENT,
    SSL_PARENT,
    ROUNDROBIN_PARENT,
    HIER_MAX
} hier_code;

typedef enum {
    ICP_OP_INVALID,		/* 00 to insure 0 doesn't get accidently interpreted. */
    ICP_OP_QUERY,		/* 01 query opcode (cl->sv) */
    ICP_OP_HIT,			/* 02 hit (cl<-sv) */
    ICP_OP_MISS,		/* 03 miss (cl<-sv) */
    ICP_OP_ERR,			/* 04 error (cl<-sv) */
    ICP_OP_SEND,		/* 05 send object non-auth (cl->sv) */
    ICP_OP_SENDA,		/* 06 send object authoritative (cl->sv) */
    ICP_OP_DATABEG,		/* 07 first data, but not last (sv<-cl) */
    ICP_OP_DATA,		/* 08 data middle of stream (sv<-cl) */
    ICP_OP_DATAEND,		/* 09 last data (sv<-cl) */
    ICP_OP_SECHO,		/* 10 echo from source (sv<-os) */
    ICP_OP_DECHO,		/* 11 echo from dumb cache (sv<-dc) */
    ICP_OP_UNUSED0,		/* 12 */
    ICP_OP_UNUSED1,		/* 13 */
    ICP_OP_UNUSED2,		/* 14 */
    ICP_OP_UNUSED3,		/* 15 */
    ICP_OP_UNUSED4,		/* 16 */
    ICP_OP_UNUSED5,		/* 17 */
    ICP_OP_UNUSED6,		/* 18 */
    ICP_OP_UNUSED7,		/* 19 */
    ICP_OP_UNUSED8,		/* 20 */
    ICP_OP_MISS_NOFETCH,	/* 21 access denied while reloading */
    ICP_OP_DENIED,		/* 22 access denied (cl<-sv) */
    ICP_OP_HIT_OBJ,		/* 23 hit with object data (cl<-sv) */
    ICP_OP_END			/* 24 marks end of opcodes */
} icp_opcode;

enum {
    NOT_IN_MEMORY,
    SWAPPING_IN,
    IN_MEMORY
};

enum {
    PING_NONE,
    PING_WAITING,
    PING_TIMEOUT,
    PING_DONE
};

enum {
    STORE_OK,
    STORE_PENDING,
    STORE_ABORTED
};

enum {
    NO_SWAP,
    SWAPPING_OUT,
    SWAP_OK
};

enum {
    METHOD_NONE,		/* 000 */
    METHOD_GET,			/* 001 */
    METHOD_POST,		/* 010 */
    METHOD_PUT,			/* 011 */
    METHOD_HEAD,		/* 100 */
    METHOD_CONNECT,		/* 101 */
    METHOD_TRACE,		/* 110 */
    METHOD_PURGE		/* 111 */
};
typedef unsigned int method_t;

typedef enum {
    PROTO_NONE,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_GOPHER,
    PROTO_WAIS,
    PROTO_CACHEOBJ,
    PROTO_ICP,
    PROTO_MAX
} protocol_t;
