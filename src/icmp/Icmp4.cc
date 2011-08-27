/*
 * $Id$
 *
 * DEBUG: section 42    ICMP Pinger program
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
//#define SQUID_HELPER 1

#include "squid.h"

#if USE_ICMP

#include "SquidTime.h"
#include "Icmp4.h"
#include "IcmpPinger.h"
#include "Debug.h"

const char *icmpPktStr[] = {
    "Echo Reply",
    "ICMP 1",
    "ICMP 2",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "ICMP 6",
    "ICMP 7",
    "Echo",
    "ICMP 9",
    "ICMP 10",
    "Time Exceeded",
    "Parameter Problem",
    "Timestamp",
    "Timestamp Reply",
    "Info Request",
    "Info Reply",
    "Out of Range Type"
};

Icmp4::Icmp4() : Icmp()
{
    ;
}

Icmp4::~Icmp4()
{
    Close();
}

int
Icmp4::Open(void)
{
    icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (icmp_sock < 0) {
        debugs(50, 0, HERE << " icmp_sock: " << xstrerror());
        return -1;
    }

    icmp_ident = getpid() & 0xffff;
    debugs(42, 1, "pinger: ICMP socket opened.");

    return icmp_sock;
}

void
Icmp4::SendEcho(IpAddress &to, int opcode, const char *payload, int len)
{
    int x;
    LOCAL_ARRAY(char, pkt, MAX_PKT4_SZ);

    struct icmphdr *icmp = NULL;
    icmpEchoData *echo;
    size_t icmp_pktsize = sizeof(struct icmphdr);
    struct addrinfo *S = NULL;

    memset(pkt, '\0', MAX_PKT4_SZ);

    icmp = (struct icmphdr *) (void *) pkt;

    /*
     * cevans - beware signed/unsigned issues in untrusted data from
     * the network!!
     */
    if (len < 0) {
        len = 0;
    }

    // Construct ICMP packet header
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = icmp_ident;
    icmp->icmp_seq = (unsigned short) icmp_pkts_sent++;

    // Construct ICMP packet data content
    echo = (icmpEchoData *) (icmp + 1);
    echo->opcode = (unsigned char) opcode;
    memcpy(&echo->tv, &current_time, sizeof(struct timeval));

    icmp_pktsize += sizeof(struct timeval) + sizeof(char);

    if (payload) {
        if (len > MAX_PAYLOAD)
            len = MAX_PAYLOAD;

        xmemcpy(echo->payload, payload, len);

        icmp_pktsize += len;
    }

    icmp->icmp_cksum = CheckSum((unsigned short *) icmp, icmp_pktsize);

    to.GetAddrInfo(S);
    ((sockaddr_in*)S->ai_addr)->sin_port = 0;
    assert(icmp_pktsize <= MAX_PKT4_SZ);

    debugs(42, 2, HERE << "Send ICMP packet to " << to << ".");

    x = sendto(icmp_sock,
               (const void *) pkt,
               icmp_pktsize,
               0,
               S->ai_addr,
               S->ai_addrlen);

    if (x < 0) {
        debugs(42, 1, HERE << "Error sending to ICMP packet to " << to << ". ERR: " << xstrerror());
    }

    Log(to, ' ', NULL, 0, 0);
}

void
Icmp4::Recv(void)
{
    int n;
    struct addrinfo *from = NULL;
    int iphdrlen = sizeof(iphdr);
    struct iphdr *ip = NULL;
    struct icmphdr *icmp = NULL;
    static char *pkt = NULL;
    struct timeval now;
    icmpEchoData *echo;
    static pingerReplyData preply;

    if (icmp_sock < 0) {
        debugs(42, 0, HERE << "No socket! Recv() should not be called.");
        return;
    }

    if (pkt == NULL)
        pkt = (char *)xmalloc(MAX_PKT4_SZ);

    preply.from.InitAddrInfo(from);
    n = recvfrom(icmp_sock,
                 (void *)pkt,
                 MAX_PKT4_SZ,
                 0,
                 from->ai_addr,
                 &from->ai_addrlen);

    preply.from = *from;

#if GETTIMEOFDAY_NO_TZP

    gettimeofday(&now);

#else

    gettimeofday(&now, NULL);

#endif

    debugs(42, 8, HERE << n << " bytes from " << preply.from);

    ip = (struct iphdr *) (void *) pkt;

#if HAVE_STRUCT_IPHDR_IP_HL

    iphdrlen = ip->ip_hl << 2;

#else /* HAVE_STRUCT_IPHDR_IP_HL */
#if WORDS_BIGENDIAN

    iphdrlen = (ip->ip_vhl >> 4) << 2;

#else

    iphdrlen = (ip->ip_vhl & 0xF) << 2;

#endif
#endif /* HAVE_STRUCT_IPHDR_IP_HL */

    icmp = (struct icmphdr *) (void *) (pkt + iphdrlen);

    if (icmp->icmp_type != ICMP_ECHOREPLY)
        return;

    if (icmp->icmp_id != icmp_ident)
        return;

    echo = (icmpEchoData *) (void *) (icmp + 1);

    preply.opcode = echo->opcode;

    preply.hops = ipHops(ip->ip_ttl);

    struct timeval tv;
    memcpy(&tv, &echo->tv, sizeof(struct timeval));
    preply.rtt = tvSubMsec(tv, now);

    preply.psize = n - iphdrlen - (sizeof(icmpEchoData) - MAX_PKT4_SZ);

    control.SendResult(preply, (sizeof(pingerReplyData) - MAX_PKT4_SZ + preply.psize) );

    Log(preply.from, icmp->icmp_type, icmpPktStr[icmp->icmp_type], preply.rtt, preply.hops);
}

#endif /* USE_ICMP */
