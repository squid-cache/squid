/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 37    ICMP Routines */

#ifndef SQUID_SRC_ICMP_ICMP6_H
#define SQUID_SRC_ICMP_ICMP6_H

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
 * Provides ECHO-REQUEST, ECHO-REPLY (section 4)
 */
class Icmp6 : public Icmp
{
public:
    Icmp6();
    ~Icmp6() override;

    int Open() override;

#if USE_ICMP
    void SendEcho(Ip::Address &, int, const char*, int) override;
    void Recv(void) override;
#endif
};

#if USE_ICMP

/// pinger helper contains one of these as a global object.
extern Icmp6 icmp6;

#endif /* USE_ICMP && SQUID_HELPER */
#endif /* SQUID_SRC_ICMP_ICMP6_H */

