/*
 * DEBUG: section 37    ICMP Routines
 * AUTHOR: Duane Wessels, Amos Jeffries
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
#ifndef _INCLUDE_ICMP_H
#define _INCLUDE_ICMP_H

#include "config.h"
#include "ip/IpAddress.h"

#define PINGER_PAYLOAD_SZ	8192

#define MAX_PAYLOAD 256 // WAS: SQUIDHOSTNAMELEN
#define MAX_PKT4_SZ (MAX_PAYLOAD + sizeof(struct timeval) + sizeof (char) + sizeof(struct icmphdr) + 1)
#define MAX_PKT6_SZ (MAX_PAYLOAD + sizeof(struct timeval) + sizeof (char) + sizeof(struct icmp6_hdr) + 1)

#if USE_ICMP

/* This is a line-data format struct. DO NOT alter. */
struct pingerEchoData {
    IpAddress to;
    unsigned char opcode;
    int psize;
    char payload[PINGER_PAYLOAD_SZ];
};

/* This is a line-data format struct. DO NOT alter. */
struct pingerReplyData {
    IpAddress from;
    unsigned char opcode;
    int rtt;
    int hops;
    int psize;
    char payload[PINGER_PAYLOAD_SZ];
};

struct icmpEchoData {
    struct timeval tv;
    unsigned char opcode;
    char payload[MAX_PAYLOAD];
};

SQUIDCEXTERN int icmp_pkts_sent;

#endif /* USE_ICMP */


/**
 * Implements the squid interface to access ICMP operations
 *
 \par
 * Child implementations define specific parts of these operations
 * using these methods as a naming and parameter template.
 *
 * IcmpSquid - implements the squid side of squid-pinger interface
 * IcmpPinger - implements the pinger side of the squid-pinger interface
 * Icmpv4 - implements pinger helper for Icmpv4
 * Icmpv6 - implements pinger helper for Icmpv6
 */
class Icmp
{
public:
    Icmp();
    virtual ~Icmp() {};

    /// Start pinger helper and initiate control channel
    virtual int Open() =0;

    /// Shutdown pinger helper and control channel
    virtual void Close();

#if USE_ICMP

    /**
     * Construct and Send an ECHO request
     *
     \param to        Destination address being 'pinged'
     \param opcode    Specific code for ECHO request, see RFC ????.
     \param payload   A payload MAY be sent in the ICMP message.
     *                Content longer than MAX_PAYLOAD will be truncated.
     \param len       Length of the payload in bytes if any is to be sent or 0.
     */
    virtual void SendEcho(IpAddress &to, int opcode, const char *payload=NULL, int len=0) =0;

    /// Handle ICMP responses.
    virtual void Recv(void) =0;

protected:
    /* shared internal methods */

    /// Calculate a packet checksum
    int CheckSum(unsigned short *ptr, int size);

    /**
     * Translate TTL to a hop distance
     *
     \param ttl	negative     : n > 33
     \param ttl	n(0...32)    : 32 >= n >= 1
     \param ttl	n(33...62)   : 32 >= n >= 1
     \param ttl	n(63...64)   : 2 >= n >= 1
     \param ttl	n(65...128)  : 64 >= n >= 1
     \param ttl	n(129...192) : 64 >= n >= 1
     \param ttl	n(193...)    : n < 255
     *
     \bug BUG? ttl<0 can produce high hop values
     \bug BUG? ttl>255 can produce zero or negative hop values
     */
    int ipHops(int ttl);

    /// Log the packet.
    void Log(const IpAddress &addr, const u_int8_t type, const char* pkt_str, const int rtt, const int hops);

    /* no use wasting memory */
    int icmp_sock;
    int icmp_ident;
#endif /* USE_ICMP */
};

#endif
