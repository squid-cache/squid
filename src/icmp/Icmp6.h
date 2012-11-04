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
#ifndef _INCLUDE_ICMPV6_H
#define _INCLUDE_ICMPV6_H

#include "Icmp.h"

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif
#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

/* see RFC 4443 section 2.1 */
#ifndef ICMP6_ECHOREQUEST
#define ICMP6_ECHOREQUEST 128
#endif

/* see RFC 4443 section 2.1 */
#ifndef ICMP6_ECHOREPLY
#define ICMP6_ECHOREPLY 129
#endif

/* see RFC 4443 section 2.1 */
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/**
 * Class partially implementing RFC 4443 - ICMPv6 for IP version 6.
 * Provides ECHO-REQUEST, ECHO-REPLY (secion 4)
 */
class Icmp6 : public Icmp
{
public:
    Icmp6();
    virtual ~Icmp6();

    virtual int Open();

#if USE_ICMP
    virtual void SendEcho(Ip::Address &, int, const char*, int);
    virtual void Recv(void);
#endif
};

#if USE_ICMP

/// pinger helper contains one of these as a global object.
extern Icmp6 icmp6;

#endif /* USE_ICMP && SQUID_HELPER */
#endif /* _INCLUDE_ICMPV6_H */
