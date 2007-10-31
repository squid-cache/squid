
/*
 * $Id: ICP.h,v 1.9 2007/10/31 04:52:15 amosjeffries Exp $
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

#include "StoreClient.h"

/**
 * This struct is the wire-level header.
 * DO NOT add more move fields on pain of breakage.
 * DO NOT add virtual methods.
 */
struct _icp_common_t
{
    unsigned char opcode;	/* opcode */
    unsigned char version;	/* version number */
    unsigned short length;	/* total length (bytes) */
    u_int32_t reqnum;		/* req number (req'd for UDP) */
    u_int32_t flags;
    u_int32_t pad;
    u_int32_t shostid;		/* sender host id */
#ifdef __cplusplus

    _icp_common_t();
    _icp_common_t(char *buf, unsigned int len);

    void handleReply(char *buf, struct sockaddr_in *from);
    static _icp_common_t *createMessage(icp_opcode opcode, int flags, const char *url, int reqnum, int pad);
    icp_opcode getOpCode() const;
#endif
};

#ifdef __cplusplus

inline icp_opcode & operator++ (icp_opcode & aCode)
{
    int tmp = (int) aCode;
    aCode = (icp_opcode) (++tmp);
    return aCode;
}


/** \todo mempool this */
class ICPState
{

public:
    ICPState(icp_common_t &, HttpRequest *);
    virtual ~ ICPState();
    icp_common_t header;
    HttpRequest *request;
    int fd;

    struct sockaddr_in from;
    char *url;
};

#endif

struct icpUdpData
{

    struct sockaddr_in address;
    void *msg;
    size_t len;
    icpUdpData *next;
#ifndef LESS_TIMING

    struct timeval start;
#endif

    log_type logcode;

    struct timeval queue_time;
};


HttpRequest* icpGetRequest(char *url, int reqnum, int fd, struct sockaddr_in *from);

int icpAccessAllowed(struct sockaddr_in *from, HttpRequest * icp_request);

SQUIDCEXTERN void icpCreateAndSend(icp_opcode, int flags, char const *url, int reqnum, int pad, int fd, const struct sockaddr_in *from);
extern icp_opcode icpGetCommonOpcode();

SQUIDCEXTERN int icpUdpSend(int, const struct sockaddr_in *, icp_common_t *, log_type, int);
SQUIDCEXTERN log_type icpLogFromICPCode(icp_opcode opcode);

void icpDenyAccess(struct sockaddr_in *from, char *url, int reqnum, int fd);
SQUIDCEXTERN PF icpHandleUdp;
SQUIDCEXTERN PF icpUdpSendQueue;

SQUIDCEXTERN void icpHandleIcpV3(int, struct sockaddr_in, char *, int);
SQUIDCEXTERN int icpCheckUdpHit(StoreEntry *, HttpRequest * request);
SQUIDCEXTERN void icpConnectionsOpen(void);
SQUIDCEXTERN void icpConnectionShutdown(void);
SQUIDCEXTERN void icpConnectionClose(void);
SQUIDCEXTERN int icpSetCacheKey(const cache_key * key);
SQUIDCEXTERN const cache_key *icpGetCacheKey(const char *url, int reqnum);


#endif /* SQUID_ICP_H */
