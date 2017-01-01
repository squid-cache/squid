/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ENUMS_H
#define SQUID_ENUMS_H

enum fd_type {
    FD_NONE,
    FD_LOG,
    FD_FILE,
    FD_SOCKET,
    FD_PIPE,
    FD_MSGHDR,
    FD_UNKNOWN
};

enum {
    FD_READ,
    FD_WRITE
};

typedef enum {
    PEER_NONE,
    PEER_SIBLING,
    PEER_PARENT,
    PEER_MULTICAST
} peer_t;

typedef enum {
    CC_BADHDR = -1,
    CC_PUBLIC = 0,
    CC_PRIVATE,
    CC_NO_CACHE,
    CC_NO_STORE,
    CC_NO_TRANSFORM,
    CC_MUST_REVALIDATE,
    CC_PROXY_REVALIDATE,
    CC_MAX_AGE,
    CC_S_MAXAGE,
    CC_MAX_STALE,
    CC_MIN_FRESH,
    CC_ONLY_IF_CACHED,
    CC_STALE_IF_ERROR,
    CC_OTHER,
    CC_ENUM_END
} http_hdr_cc_type;

typedef enum {
    SC_NO_STORE,
    SC_NO_STORE_REMOTE,
    SC_MAX_AGE,
    SC_CONTENT,
    SC_OTHER,
    SC_ENUM_END
} http_hdr_sc_type;

typedef enum _mem_status_t {
    NOT_IN_MEMORY,
    IN_MEMORY
} mem_status_t;

typedef enum {
    PING_NONE,
    PING_WAITING,
    PING_DONE
} ping_status_t;

typedef enum {
    STORE_OK,
    STORE_PENDING
} store_status_t;

typedef enum {
    SWAPOUT_NONE,
    SWAPOUT_WRITING,
    SWAPOUT_DONE
} swap_status_t;

typedef enum {
    STORE_NON_CLIENT,
    STORE_MEM_CLIENT,
    STORE_DISK_CLIENT
} store_client_t;

/*
 * These are for StoreEntry->flag, which is defined as a SHORT
 *
 * NOTE: These flags are written to swap.state, so think very carefully
 * about deleting or re-assigning!
 */
enum {
    ENTRY_SPECIAL,
    ENTRY_REVALIDATE_ALWAYS,
    DELAY_SENDING,
    RELEASE_REQUEST,
    REFRESH_REQUEST,
    ENTRY_REVALIDATE_STALE,
    ENTRY_DISPATCHED,
    KEY_PRIVATE,
    ENTRY_FWD_HDR_WAIT,
    ENTRY_NEGCACHED,
    ENTRY_VALIDATED,
    ENTRY_BAD_LENGTH,
    ENTRY_ABORTED
};

/*
 * These are for client Streams. Each node in the stream can be queried for
 * its status
 */
typedef enum {
    STREAM_NONE,        /* No particular status */
    STREAM_COMPLETE,        /* All data has been flushed, no more reads allowed */
    /* an unpredicted end has occured, no more
     * reads occured, but no need to tell
     * downstream that an error occured
     */
    STREAM_UNPLANNED_COMPLETE,
    /* An error has occured in this node or an above one,
     * and the node is not generating an error body / it's
     * midstream
     */
    STREAM_FAILED
} clientStream_status_t;

/* stateful helper callback response codes */
typedef enum {
    S_HELPER_UNKNOWN,
    S_HELPER_RESERVE,
    S_HELPER_RELEASE
} stateful_helper_callback_t;

#if SQUID_SNMP
enum {
    SNMP_C_VIEW,
    SNMP_C_USER,
    SNMP_C_COMMUNITY
};
#endif /* SQUID_SNMP */

typedef enum {
    MEM_NONE,
    MEM_2K_BUF,
    MEM_4K_BUF,
    MEM_8K_BUF,
    MEM_16K_BUF,
    MEM_32K_BUF,
    MEM_64K_BUF,
    MEM_ACL_DENY_INFO_LIST,
    MEM_ACL_NAME_LIST,
#if USE_CACHE_DIGESTS
    MEM_CACHE_DIGEST,
#endif
    MEM_CLIENT_INFO,
    MEM_LINK_LIST,
    MEM_DLINK_NODE,
    MEM_DREAD_CTRL,
    MEM_DWRITE_Q,
    MEM_HTTP_HDR_CONTENT_RANGE,
    MEM_MD5_DIGEST,
    MEM_NETDBENTRY,
    MEM_NET_DB_NAME,
    MEM_RELIST,
    // IMPORTANT: leave this here. pools above are initialized early with memInit()
    MEM_DONTFREE,
    // following pools are initialized late by their component if needed (or never)
    MEM_FQDNCACHE_ENTRY,
    MEM_IDNS_QUERY,
    MEM_IPCACHE_ENTRY,
    MEM_MAX
} mem_type;

enum {
    STORE_LOG_CREATE,
    STORE_LOG_SWAPIN,
    STORE_LOG_SWAPOUT,
    STORE_LOG_RELEASE,
    STORE_LOG_SWAPOUTFAIL
};

/* parse state of HttpReply or HttpRequest */
typedef enum {
    psReadyToParseStartLine = 0,
    psReadyToParseHeaders,
    psParsed,
    psError
} HttpMsgParseState;

enum {
    PCTILE_HTTP,
    PCTILE_ICP_QUERY,
    PCTILE_DNS,
    PCTILE_HIT,
    PCTILE_MISS,
    PCTILE_NM,
    PCTILE_NH,
    PCTILE_ICP_REPLY
};

enum {
    SENT,
    RECV
};

/*
 * These are field indicators for raw cache-cache netdb transfers
 */
enum {
    NETDB_EX_NONE,
    NETDB_EX_NETWORK,
    NETDB_EX_RTT,
    NETDB_EX_HOPS
};

/*
 * Return codes from checkVary(request)
 */
enum {
    VARY_NONE,
    VARY_MATCH,
    VARY_OTHER,
    VARY_CANCEL
};

/*
 * Store digest state enum
 */
typedef enum {
    DIGEST_READ_NONE,
    DIGEST_READ_REPLY,
    DIGEST_READ_HEADERS,
    DIGEST_READ_CBLOCK,
    DIGEST_READ_MASK,
    DIGEST_READ_DONE
} digest_read_state_t;

/* Distinguish between Request and Reply (for header mangling) */
enum {
    ROR_REQUEST,
    ROR_REPLY
};

/* CygWin & Windows NT Port */
#if _SQUID_WINDOWS_
/*
 * Supported Windows OS types codes
 */
enum {
    _WIN_OS_UNKNOWN,
    _WIN_OS_WIN32S,
    _WIN_OS_WIN95,
    _WIN_OS_WIN98,
    _WIN_OS_WINME,
    _WIN_OS_WINNT,
    _WIN_OS_WIN2K,
    _WIN_OS_WINXP,
    _WIN_OS_WINNET,
    _WIN_OS_WINLON,
    _WIN_OS_WIN7
};
#endif /* _SQUID_WINDOWS_ */

enum {
    DISABLE_PMTU_OFF,
    DISABLE_PMTU_ALWAYS,
    DISABLE_PMTU_TRANSPARENT
};

#if USE_HTCP
/*
 * TODO: This should be in htcp.h
 */
typedef enum {
    HTCP_CLR_PURGE,
    HTCP_CLR_INVALIDATION
} htcp_clr_reason;
#endif /* USE_HTCP */

#endif /* SQUID_ENUMS_H */

