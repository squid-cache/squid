/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 37    ICMP Routines */

#ifndef _INCLUDE_ICMPV4_H
#define _INCLUDE_ICMPV4_H

#include "Icmp.h"

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if !_SQUID_LINUX_ && !_SQUID_WINDOWS_
#define icmphdr icmp
#define iphdr ip
#endif

/* Linux uses its own field names. */
#if _SQUID_LINUX_
#ifdef icmp_id
#undef icmp_id
#endif
#ifdef icmp_seq
#undef icmp_seq
#endif
#define icmp_type type
#define icmp_code code
#define icmp_cksum checksum
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
#define ip_hl ihl
#define ip_v version
#define ip_tos tos
#define ip_len tot_len
#define ip_id id
#define ip_off frag_off
#define ip_ttl ttl
#define ip_p protocol
#define ip_sum check
#define ip_src saddr
#define ip_dst daddr
#endif

/* Native Windows port doesn't have netinet support, so we emulate it.
   At this time, Cygwin lacks icmp support in its include files, so we need
   to use the native Windows port definitions.
 */

#if _SQUID_WINDOWS_
#include "fde.h"

#if _SQUID_WINDOWS_

#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
#include <process.h>

#endif

/* IP Header */
typedef struct iphdr {

uint8_t  ip_vhl:
    4;          /* Length of the header in dwords */

uint8_t  version:
    4;  /* Version of IP                  */
    uint8_t  tos;              /* Type of service                */
    uint16_t total_len;        /* Length of the packet in dwords */
    uint16_t ident;            /* unique identifier              */
    uint16_t flags;            /* Flags                          */
    uint8_t  ip_ttl;           /* Time to live                   */
    uint8_t  proto;            /* Protocol number (TCP, UDP etc) */
    uint16_t checksum;         /* IP checksum                    */
    uint32_t source_ip;
    uint32_t dest_ip;
} iphdr;

/* ICMP header */
typedef struct icmphdr {
    uint8_t  icmp_type;        /* ICMP packet type                 */
    uint8_t  icmp_code;        /* Type sub code                    */
    uint16_t icmp_cksum;
    uint16_t icmp_id;
    uint16_t icmp_seq;
    uint32_t timestamp;        /* not part of ICMP, but we need it */
} icmphdr;

#endif  /* _SQUID_WINDOWS_ */

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

/* some OS apparently define icmp instead of icmphdr */
#if !defined(icmphdr) && defined(icmp)
#define icmphdr icmp
#endif

/* some OS apparently define ip instead of iphdr */
#if !defined(iphdr) && defined(ip)
#define iphdr ip
#endif

/**
 * Class partially implementing RFC 792 - ICMP for IP version 4.
 * Provides ECHO-REQUEST, ECHO-REPLY (secion 4.1)
 */
class Icmp4 : public Icmp
{
public:
    Icmp4();
    virtual ~Icmp4();

    virtual int Open();

#if USE_ICMP
    virtual void SendEcho(Ip::Address &, int, const char*, int);
    virtual void Recv(void);
#endif
};

#if USE_ICMP

/// pinger helper contains one of these as a global object.
extern Icmp4 icmp4;

#endif /* USE_ICMP && SQUID_HELPER */

#endif

