/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTCP_H
#define SQUID_HTCP_H

#if USE_HTCP

#include "HttpHeader.h"
#include "HttpRequestMethod.h"
#include "ip/forward.h"

class HttpRequest;

/// \ingroup ServerProtocolHTCP
class HtcpReplyData
{

public:
    HtcpReplyData();
    int hit;
    HttpHeader hdr;
    uint32_t msg_id;
    double version;

    struct cto_t {
        /* cache-to-origin */
        double rtt;
        int samp;
        int hops;
    } cto;
};

/// \ingroup ServerProtocolHTCP
void neighborsHtcpReply(const cache_key *, HtcpReplyData *, const Ip::Address &);

/// \ingroup ServerProtocolHTCP
void htcpOpenPorts(void);

/**
 * \ingroup ServerProtocolHTCP
 *
 * Generate and Send an HTCP query to the specified peer.
 *
 * \param e
 * \param req
 * \param p
 * \retval 1    Successfully sent request.
 * \retval 0    Unable to send request at this time. HTCP may be shutting down or starting up.
 *      Don't wait for a reply or count in stats as sent.
 * \retval -1   Error sending request.
 */
int htcpQuery(StoreEntry * e, HttpRequest * req, CachePeer * p);

/// \ingroup ServerProtocolHTCP
void htcpClear(StoreEntry * e, const char *uri, HttpRequest * req, const HttpRequestMethod &method, CachePeer * p, htcp_clr_reason reason);

/// \ingroup ServerProtocolHTCP
void htcpSocketShutdown(void);

/// \ingroup ServerProtocolHTCP
void htcpClosePorts(void);

#endif /* USE_HTCP */

#endif /* SQUID_HTCP_H */

