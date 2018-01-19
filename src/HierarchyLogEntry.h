/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHIERARCHYLOGENTRY_H
#define SQUID_HTTPHIERARCHYLOGENTRY_H

#include "comm/Connection.h"
#include "enums.h"
#include "hier_code.h"
#include "http/StatusCode.h"
#include "lookup_t.h"
#include "PingData.h"
#include "rfc2181.h"

class HierarchyLogEntry
{

public:
    HierarchyLogEntry();
    ~HierarchyLogEntry() { tcpServer = NULL; };

    /// Record details from a new server connection.
    /// call this whenever the destination server changes.
    void note(const Comm::ConnectionPointer &server, const char *requestedHost);

    /// Start recording total time spent communicating with peers
    void startPeerClock();
    /**
     * Record total time spent communicating with peers
     * \param force whether to overwrite old recorded value if any
     */
    void stopPeerClock(const bool force);

    /// Return the total time spent communicating with peers
    int64_t totalResponseTime();

public:
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    ping_data ping;
    char cd_host[SQUIDHOSTNAMELEN]; /* the host of selected by cd peer */
    lookup_t cd_lookup;     /* cd prediction: none, miss, hit */
    int n_choices;      /* #peers we selected from (cd only) */
    int n_ichoices;     /* #peers with known rtt we selected from (cd only) */

    struct timeval peer_select_start;

    struct timeval store_complete_stop;

    Http::StatusCode peer_reply_status; ///< last HTTP status code received
    timeval peer_http_request_sent; ///< last peer finished writing req
    int64_t peer_response_time; ///< last peer response delay
    Comm::ConnectionPointer tcpServer; ///< TCP/IP level details of the last peer/server connection
    int64_t bodyBytesRead;  ///< number of body bytes received from the next hop or -1

private:
    timeval firstConnStart_; ///< first connection use among all peers
    int64_t totalResponseTime_; ///< cumulative for all peers
};

#endif /* SQUID_HTTPHIERARCHYLOGENTRY_H */

