/*
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

#ifndef SQUID_HTCP_H
#define SQUID_HTCP_H

#if USE_HTCP

#include "HttpHeader.h"

class IpAddress;

/// \ingroup ServerProtocolHTCP
class HtcpReplyData
{

public:
    HtcpReplyData();
    int hit;
    HttpHeader hdr;
    u_int32_t msg_id;
    double version;

    struct cto_t {
        /* cache-to-origin */
        double rtt;
        int samp;
        int hops;
    } cto;
};

/// \bug redundant typedef
typedef class HtcpReplyData htcpReplyData;

/// \ingroup ServerProtocolHTCP
SQUIDCEXTERN void neighborsHtcpReply(const cache_key *, htcpReplyData *, const IpAddress &);

/// \ingroup ServerProtocolHTCP
SQUIDCEXTERN void htcpInit(void);

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
 * 		Don't wait for a reply or count in stats as sent.
 * \retval -1   Error sending request.
 */
SQUIDCEXTERN int htcpQuery(StoreEntry * e, HttpRequest * req, peer * p);

/// \ingroup ServerProtocolHTCP
SQUIDCEXTERN void htcpClear(StoreEntry * e, const char *uri, HttpRequest * req, const HttpRequestMethod &method, peer * p, htcp_clr_reason reason);

/// \ingroup ServerProtocolHTCP
SQUIDCEXTERN void htcpSocketShutdown(void);

/// \ingroup ServerProtocolHTCP
SQUIDCEXTERN void htcpSocketClose(void);

#endif /* USE_HTCP */

#endif /* SQUID_HTCP_H */
