/*
 * $Id$
 *
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
#ifndef _INCLUDE_ICMPV4_H
#define _INCLUDE_ICMPV4_H

#include "config.h"
#include "Icmp.h"

#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifndef _SQUID_LINUX_
#ifndef _SQUID_CYGWIN_
#ifndef _SQUID_MSWIN_
#define icmphdr icmp
#define iphdr ip
#endif
#endif
#endif

/* Linux uses its own field names. */
#if defined (_SQUID_LINUX_)
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

#ifdef _SQUID_WIN32_

#include "fde.h"

#ifdef _SQUID_MSWIN_

#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <process.h>

#endif

/* IP Header */
typedef struct iphdr {

u_int8_t  ip_vhl:
    4;          /* Length of the header in dwords */

u_int8_t  version:
    4;  /* Version of IP                  */
    u_int8_t  tos;              /* Type of service                */
    u_int16_t total_len;        /* Length of the packet in dwords */
    u_int16_t ident;            /* unique identifier              */
    u_int16_t flags;            /* Flags                          */
    u_int8_t  ip_ttl;           /* Time to live                   */
    u_int8_t  proto;            /* Protocol number (TCP, UDP etc) */
    u_int16_t checksum;         /* IP checksum                    */
    u_int32_t source_ip;
    u_int32_t dest_ip;
} iphdr;

/* ICMP header */
typedef struct icmphdr {
    u_int8_t  icmp_type;        /* ICMP packet type                 */
    u_int8_t  icmp_code;        /* Type sub code                    */
    u_int16_t icmp_cksum;
    u_int16_t icmp_id;
    u_int16_t icmp_seq;
    u_int32_t timestamp;        /* not part of ICMP, but we need it */
} icmphdr;

#endif  /* _SQUID_MSWIN_ */

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
    virtual void SendEcho(IpAddress &, int, const char*, int);
    virtual void Recv(void);
#endif
};

#if USE_ICMP

/// pinger helper contains one of these as a global object.
SQUIDCEXTERN Icmp4 icmp4;

#endif /* USE_ICMP && SQUID_HELPER */

#endif
