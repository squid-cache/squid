/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 42    ICMP Pinger program */

//#define SQUID_HELPER 1

#include "squid.h"

#if USE_ICMP

#include "Debug.h"
#include "Icmp4.h"
#include "IcmpPinger.h"
#include "leakcheck.h"
#include "SquidTime.h"

static const char *
IcmpPacketType(uint8_t v)
{
    static const char *icmpPktStr[] = {
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

    if (v > 17) {
        static char buf[50];
        snprintf(buf, sizeof(buf), "ICMP %u (invalid)", v);
        return buf;
    }

    return icmpPktStr[v];
}

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
        int xerrno = errno;
        debugs(50, DBG_CRITICAL, MYNAME << " icmp_sock: " << xstrerr(xerrno));
        return -1;
    }

    icmp_ident = getpid() & 0xffff;
    debugs(42, DBG_IMPORTANT, "pinger: ICMP socket opened.");

    return icmp_sock;
}

void
Icmp4::SendEcho(Ip::Address &to, int opcode, const char *payload, int len)
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
    icmp->icmp_seq = (unsigned short) icmp_pkts_sent;
    ++icmp_pkts_sent;

    // Construct ICMP packet data content
    echo = (icmpEchoData *) (icmp + 1);
    echo->opcode = (unsigned char) opcode;
    memcpy(&echo->tv, &current_time, sizeof(struct timeval));

    icmp_pktsize += sizeof(struct timeval) + sizeof(char);

    if (payload) {
        if (len > MAX_PAYLOAD)
            len = MAX_PAYLOAD;

        memcpy(echo->payload, payload, len);

        icmp_pktsize += len;
    }

    icmp->icmp_cksum = CheckSum((unsigned short *) icmp, icmp_pktsize);

    to.getAddrInfo(S);
    ((sockaddr_in*)S->ai_addr)->sin_port = 0;
    assert(icmp_pktsize <= MAX_PKT4_SZ);

    debugs(42, 5, HERE << "Send ICMP packet to " << to << ".");

    x = sendto(icmp_sock,
               (const void *) pkt,
               icmp_pktsize,
               0,
               S->ai_addr,
               S->ai_addrlen);

    if (x < 0) {
        int xerrno = errno;
        debugs(42, DBG_IMPORTANT, MYNAME << "ERROR: sending to ICMP packet to " << to << ": " << xstrerr(xerrno));
    }

    Log(to, ' ', NULL, 0, 0);
    Ip::Address::FreeAddr(S);
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
        debugs(42, DBG_CRITICAL, HERE << "No socket! Recv() should not be called.");
        return;
    }

    if (pkt == NULL)
        pkt = (char *)xmalloc(MAX_PKT4_SZ);

    Ip::Address::InitAddr(from);
    n = recvfrom(icmp_sock,
                 (void *)pkt,
                 MAX_PKT4_SZ,
                 0,
                 from->ai_addr,
                 &from->ai_addrlen);

    if (n <= 0) {
        debugs(42, DBG_CRITICAL, HERE << "Error when calling recvfrom() on ICMP socket.");
        Ip::Address::FreeAddr(from);
        return;
    }

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

    if (icmp->icmp_type != ICMP_ECHOREPLY) {
        Ip::Address::FreeAddr(from);
        return;
    }

    if (icmp->icmp_id != icmp_ident) {
        Ip::Address::FreeAddr(from);
        return;
    }

    echo = (icmpEchoData *) (void *) (icmp + 1);

    preply.opcode = echo->opcode;

    preply.hops = ipHops(ip->ip_ttl);

    struct timeval tv;
    memcpy(&tv, &echo->tv, sizeof(struct timeval));
    preply.rtt = tvSubMsec(tv, now);

    preply.psize = n - iphdrlen - (sizeof(icmpEchoData) - MAX_PKT4_SZ);

    if (preply.psize < 0) {
        debugs(42, DBG_CRITICAL, HERE << "Malformed ICMP packet.");
        Ip::Address::FreeAddr(from);
        return;
    }

    control.SendResult(preply, (sizeof(pingerReplyData) - MAX_PKT4_SZ + preply.psize) );

    Log(preply.from, icmp->icmp_type, IcmpPacketType(icmp->icmp_type), preply.rtt, preply.hops);
    Ip::Address::FreeAddr(from);
}

#endif /* USE_ICMP */

