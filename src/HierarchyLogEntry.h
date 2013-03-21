/*
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_HTTPHIERARCHYLOGENTRY_H
#define SQUID_HTTPHIERARCHYLOGENTRY_H

#include "comm/Connection.h"
#include "enums.h"
#include "hier_code.h"
#include "http/StatusCode.h"
#include "lookup_t.h"
#include "rfc2181.h"
#include "PingData.h"

class HierarchyLogEntry
{

public:
    HierarchyLogEntry();
    ~HierarchyLogEntry() { tcpServer = NULL; };

    /// Record details from a new server connection.
    /// call this whenever the destination server changes.
    void note(const Comm::ConnectionPointer &server, const char *requestedHost);

public:
    hier_code code;
    char host[SQUIDHOSTNAMELEN];
    ping_data ping;
    char cd_host[SQUIDHOSTNAMELEN];	/* the host of selected by cd peer */
    lookup_t cd_lookup;		/* cd prediction: none, miss, hit */
    int n_choices;		/* #peers we selected from (cd only) */
    int n_ichoices;		/* #peers with known rtt we selected from (cd only) */

    struct timeval peer_select_start;

    struct timeval store_complete_stop;

    Http::StatusCode peer_reply_status; ///< last HTTP status code received
    timeval peer_http_request_sent; ///< last peer finished writing req
    int64_t peer_response_time; ///< last peer response delay
    timeval first_conn_start; ///< first connection use among all peers
    int64_t total_response_time; ///< cumulative for all peers
    Comm::ConnectionPointer tcpServer; ///< TCP/IP level details of the last server-side connection
    int64_t bodyBytesRead;  ///< number of body bytes received from the next hop or -1
};

#endif /* SQUID_HTTPHIERARCHYLOGENTRY_H */
