/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ENUMS_H
#define SQUID_ENUMS_H

enum fd_type {
    FD_NONE_TYPE,
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

/// StoreEntry relationship with a disk cache
typedef enum {
    /// StoreEntry is currently not associated with any disk store entry.
    /// Does not guarantee (or preclude!) a matching disk store entry existence.
    SWAPOUT_NONE,
    /// StoreEntry is being swapped out to the associated disk store entry.
    /// Guarantees the disk store entry existence.
    SWAPOUT_WRITING,
    /// StoreEntry is associated with a complete (i.e., fully swapped out) disk store entry.
    /// Guarantees the disk store entry existence.
    SWAPOUT_DONE,
    /// StoreEntry is associated with an unusable disk store entry.
    /// Swapout attempt has failed. The entry should be marked for eventual deletion.
    /// Guarantees the disk store entry existence.
    SWAPOUT_FAILED
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

    /// Tiny Store writes are likely. The writes should be aggregated together
    /// before Squid announces the new content availability to the store
    /// clients. For example, forming a cached HTTP response header may result
    /// in dozens of StoreEntry::write() calls, many of which adding as little
    /// as two bytes. Sharing those small writes with the store clients
    /// increases overhead, especially because the client code can do nothing
    /// useful with the written content until the whole response header is
    /// stored. Might be combined with ENTRY_FWD_HDR_WAIT. TODO: Rename to
    /// ENTRY_DELAY_WHILE_COALESCING to emphasize the difference from and
    /// similarity with ENTRY_FWD_HDR_WAIT.
    DELAY_SENDING,
    RELEASE_REQUEST, ///< prohibits making the key public
    REFRESH_REQUEST,
    ENTRY_REVALIDATE_STALE,
    ENTRY_DISPATCHED,
    KEY_PRIVATE,

    /// The current entry response may change. The contents of an entry in this
    /// state must not be shared with its store clients. For example, Squid
    /// receives (and buffers) an HTTP/504 response but may decide to retry that
    /// transaction to receive a successful response from another server
    /// instead. Might be combined with DELAY_SENDING. TODO: Rename to
    /// ENTRY_DELAY_WHILE_WOBBLING to emphasize the difference from and
    /// similarity with DELAY_SENDING.
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
    /* an unpredicted end has occurred, no more
     * reads occurred, but no need to tell
     * downstream that an error occurred
     */
    STREAM_UNPLANNED_COMPLETE,
    /* An error has occurred in this node or an above one,
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

