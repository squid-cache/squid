
/*
 * $Id$
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

#ifndef SQUID_ENUMS_H
#define SQUID_ENUMS_H

#include "HttpStatusCode.h"

typedef enum {
    LOG_TAG_NONE,
    LOG_TCP_HIT,
    LOG_TCP_MISS,
    LOG_TCP_REFRESH_UNMODIFIED, // refresh from origin revalidated existing entry
    LOG_TCP_REFRESH_FAIL,       // refresh from origin failed
    LOG_TCP_REFRESH_MODIFIED,   // refresh from origin replaced existing entry
    LOG_TCP_CLIENT_REFRESH_MISS,
    LOG_TCP_IMS_HIT,
    LOG_TCP_SWAPFAIL_MISS,
    LOG_TCP_NEGATIVE_HIT,
    LOG_TCP_MEM_HIT,
    LOG_TCP_DENIED,
    LOG_TCP_DENIED_REPLY,
    LOG_TCP_OFFLINE_HIT,
#if LOG_TCP_REDIRECTS
    LOG_TCP_REDIRECT,
#endif
    LOG_UDP_HIT,
    LOG_UDP_MISS,
    LOG_UDP_DENIED,
    LOG_UDP_INVALID,
    LOG_UDP_MISS_NOFETCH,
    LOG_ICP_QUERY,
    LOG_TYPE_MAX
} log_type;

typedef enum {
    ERR_NONE,
    ERR_READ_TIMEOUT,
    ERR_LIFETIME_EXP,
    ERR_READ_ERROR,
    ERR_WRITE_ERROR,
    ERR_SHUTTING_DOWN,
    ERR_CONNECT_FAIL,
    ERR_SECURE_CONNECT_FAIL,
    ERR_INVALID_REQ,
    ERR_UNSUP_REQ,
    ERR_INVALID_URL,
    ERR_SOCKET_FAILURE,
    ERR_DNS_FAIL,
    ERR_CANNOT_FORWARD,
    ERR_FORWARDING_DENIED,
    ERR_NO_RELAY,
    ERR_ZERO_SIZE_OBJECT,
    ERR_FTP_DISABLED,
    ERR_FTP_FAILURE,
    ERR_URN_RESOLVE,
    ERR_ACCESS_DENIED,
    ERR_CACHE_ACCESS_DENIED,
    ERR_CACHE_MGR_ACCESS_DENIED,
    ERR_SQUID_SIGNATURE,	/* not really an error */
    ERR_FTP_PUT_CREATED,	/* !error,a note that the file was created */
    ERR_FTP_PUT_MODIFIED,	/* modified, !created */
    ERR_FTP_PUT_ERROR,
    ERR_FTP_NOT_FOUND,
    ERR_FTP_FORBIDDEN,
    ERR_FTP_UNAVAILABLE,
    ERR_ONLY_IF_CACHED_MISS,	/* failure to satisfy only-if-cached request */
    ERR_TOO_BIG,
    TCP_RESET,
    ERR_ESI,                    /* Failure to perform ESI processing */
    ERR_INVALID_RESP,
    ERR_ICAP_FAILURE,
    ERR_UNSUP_HTTPVERSION,     /* HTTP version is not supported */
    ERR_MAX
} err_type;

enum fd_type {
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

typedef enum {
    PEER_NONE,
    PEER_SIBLING,
    PEER_PARENT,
    PEER_MULTICAST
} peer_t;

typedef enum {
    LOOKUP_NONE,
    LOOKUP_HIT,
    LOOKUP_MISS
} lookup_t;

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
    CC_ONLY_IF_CACHED,
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

typedef enum {
    HIER_NONE,
    HIER_DIRECT,
    SIBLING_HIT,
    PARENT_HIT,
    DEFAULT_PARENT,
    SINGLE_PARENT,
    FIRSTUP_PARENT,
    FIRST_PARENT_MISS,
    CLOSEST_PARENT_MISS,
    CLOSEST_PARENT,
    CLOSEST_DIRECT,
    NO_DIRECT_FAIL,
    SOURCE_FASTEST,
    ROUNDROBIN_PARENT,
#if USE_CACHE_DIGESTS
    CD_PARENT_HIT,
    CD_SIBLING_HIT,
#endif
    CARP,
    ANY_OLD_PARENT,
    USERHASH_PARENT,
    SOURCEHASH_PARENT,
    PINNED,
    HIER_MAX
} hier_code;

/// \ingroup ServerProtocolICPAPI
typedef enum {
    ICP_INVALID,
    ICP_QUERY,
    ICP_HIT,
    ICP_MISS,
    ICP_ERR,
    ICP_SEND,
    ICP_SENDA,
    ICP_DATABEG,
    ICP_DATA,
    ICP_DATAEND,
    ICP_SECHO,
    ICP_DECHO,
    ICP_NOTIFY,
    ICP_INVALIDATE,
    ICP_DELETE,
    ICP_UNUSED15,
    ICP_UNUSED16,
    ICP_UNUSED17,
    ICP_UNUSED18,
    ICP_UNUSED19,
    ICP_UNUSED20,
    ICP_MISS_NOFETCH,
    ICP_DENIED,
    ICP_HIT_OBJ,
    ICP_END
} icp_opcode;

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

typedef enum {
    PROTO_NONE,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_GOPHER,
    PROTO_WAIS,
    PROTO_CACHEOBJ,
    PROTO_ICP,
#if USE_HTCP
    PROTO_HTCP,
#endif
    PROTO_URN,
    PROTO_WHOIS,
    PROTO_INTERNAL,
    PROTO_HTTPS,
    PROTO_ICY,
    PROTO_MAX
} protocol_t;

/*
 * These are for StoreEntry->flag, which is defined as a SHORT
 *
 * NOTE: These flags are written to swap.state, so think very carefully
 * about deleting or re-assigning!
 */
enum {
    ENTRY_SPECIAL,
    ENTRY_REVALIDATE,
    DELAY_SENDING,
    RELEASE_REQUEST,
    REFRESH_REQUEST,
    ENTRY_CACHABLE,
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
    STREAM_NONE,		/* No particular status */
    STREAM_COMPLETE,		/* All data has been flushed, no more reads allowed */
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

typedef enum {
    AUTH_ACL_CHALLENGE = -2,
    AUTH_ACL_HELPER = -1,
    AUTH_ACL_CANNOT_AUTHENTICATE = 0,
    AUTH_AUTHENTICATED = 1
} auth_acl_t;

typedef enum {
    AUTH_UNKNOWN,		/* default */
    AUTH_BASIC,
    AUTH_NTLM,
    AUTH_DIGEST,
    AUTH_NEGOTIATE,
    AUTH_BROKEN			/* known type, but broken data */
} auth_type_t;

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

#endif

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
    MEM_DONTFREE,
    MEM_DREAD_CTRL,
    MEM_DWRITE_Q,
    MEM_FQDNCACHE_ENTRY,
    MEM_FWD_SERVER,
    MEM_HTTP_HDR_CC,
    MEM_HTTP_HDR_CONTENT_RANGE,
    MEM_IPCACHE_ENTRY,
    MEM_MD5_DIGEST,
    MEM_NETDBENTRY,
    MEM_NET_DB_NAME,
    MEM_RELIST,
#if !USE_DNSSERVERS
    MEM_IDNS_QUERY,
#endif
    MEM_MAX
} mem_type;

enum {
    STORE_LOG_CREATE,
    STORE_LOG_SWAPIN,
    STORE_LOG_SWAPOUT,
    STORE_LOG_RELEASE,
    STORE_LOG_SWAPOUTFAIL
};

typedef enum {
    SWAP_LOG_NOP,
    SWAP_LOG_ADD,
    SWAP_LOG_DEL,
    SWAP_LOG_VERSION,
    SWAP_LOG_MAX
} swap_log_op;


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
#ifdef _SQUID_WIN32_
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

#endif

typedef enum {
    CLF_UNKNOWN,
    CLF_AUTO,
    CLF_CUSTOM,
    CLF_SQUID,
    CLF_COMMON,
#if ICAP_CLIENT
    CLF_ICAP_SQUID,
#endif
    CLF_NONE
} customlog_type;

enum {
    DISABLE_PMTU_OFF,
    DISABLE_PMTU_ALWAYS,
    DISABLE_PMTU_TRANSPARENT
};

#if USE_HTCP
/*
 * This should be in htcp.h but because neighborsHtcpClear is defined in
 * protos.h it has to be here.
 */
typedef enum {
    HTCP_CLR_PURGE,
    HTCP_CLR_INVALIDATION
} htcp_clr_reason;
#endif

#endif /* SQUID_ENUMS_H */
