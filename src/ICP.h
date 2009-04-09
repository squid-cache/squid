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

#ifndef SQUID_ICP_H
#define SQUID_ICP_H

/**
 \defgroup ServerProtocolICPAPI ICP
 \ingroup ServerProtocol
 */

#include "StoreClient.h"

/**
 \ingroup ServerProtocolICPAPI
 *
 * This struct is the wire-level header.
 * DO NOT add more move fields on pain of breakage.
 * DO NOT add virtual methods.
 */
struct _icp_common_t {
    /** opcode */
    unsigned char opcode;
    /** version number */
    unsigned char version;
    /** total length (bytes) */
    unsigned short length;
    /** req number (req'd for UDP) */
    u_int32_t reqnum;
    u_int32_t flags;
    u_int32_t pad;
    /** sender host id */
    u_int32_t shostid;

/// \todo I don't believe this header is included in non-c++ code anywhere
///		the struct should become a public POD class and kill these ifdef.
#ifdef __cplusplus

    _icp_common_t();
    _icp_common_t(char *buf, unsigned int len);

    void handleReply(char *buf, IpAddress &from);
    static _icp_common_t *createMessage(icp_opcode opcode, int flags, const char *url, int reqnum, int pad);
    icp_opcode getOpCode() const;
#endif
};

#ifdef __cplusplus

/// \ingroup ServerProtocolICPAPI
inline icp_opcode & operator++ (icp_opcode & aCode)
{
    int tmp = (int) aCode;
    aCode = (icp_opcode) (++tmp);
    return aCode;
}


/**
 \ingroup ServerProtocolICPAPI
 \todo mempool this
 */
class ICPState
{

public:
    ICPState(icp_common_t &aHeader, HttpRequest *aRequest);
    virtual ~ICPState();
    icp_common_t header;
    HttpRequest *request;
    int fd;

    IpAddress from;
    char *url;
};

#endif

/// \ingroup ServerProtocolICPAPI
struct icpUdpData {
    IpAddress address;
    void *msg;
    size_t len;
    icpUdpData *next;
#ifndef LESS_TIMING

    struct timeval start;
#endif

    log_type logcode;

    struct timeval queue_time;
};

/// \ingroup ServerProtocolICPAPI
HttpRequest* icpGetRequest(char *url, int reqnum, int fd, IpAddress &from);

/// \ingroup ServerProtocolICPAPI
int icpAccessAllowed(IpAddress &from, HttpRequest * icp_request);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN void icpCreateAndSend(icp_opcode, int flags, char const *url, int reqnum, int pad, int fd, const IpAddress &from);

/// \ingroup ServerProtocolICPAPI
extern icp_opcode icpGetCommonOpcode();

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN int icpUdpSend(int, const IpAddress &, icp_common_t *, log_type, int);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN log_type icpLogFromICPCode(icp_opcode opcode);

/// \ingroup ServerProtocolICPAPI
void icpDenyAccess(IpAddress &from, char *url, int reqnum, int fd);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN PF icpHandleUdp;

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN PF icpUdpSendQueue;

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN void icpHandleIcpV3(int, IpAddress &, char *, int);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN int icpCheckUdpHit(StoreEntry *, HttpRequest * request);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN void icpConnectionsOpen(void);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN void icpConnectionShutdown(void);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN void icpConnectionClose(void);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN int icpSetCacheKey(const cache_key * key);

/// \ingroup ServerProtocolICPAPI
SQUIDCEXTERN const cache_key *icpGetCacheKey(const char *url, int reqnum);

#endif /* SQUID_ICP_H */
