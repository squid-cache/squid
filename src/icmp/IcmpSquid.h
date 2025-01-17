/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 37    ICMP Routines */

#ifndef SQUID_SRC_ICMP_ICMPSQUID_H
#define SQUID_SRC_ICMP_ICMPSQUID_H

#include "Icmp.h"

/**
 * Implements a non-blocking pseudo-ICMP engine for squid internally.
 *
 * Rather than doing all the work itself it passes each request off to
 * an external pinger helper and returns results form that helper to squid.
 *
 * Provides ECHO-REQUEST, ECHO-REPLY in a protocol-neutral manner.
 */
class IcmpSquid : public Icmp
{
public:
    IcmpSquid();
    ~IcmpSquid() override;

    int Open() override;
    void Close() override;

    void DomainPing(Ip::Address &to, const char *domain);

#if USE_ICMP
    void SendEcho(Ip::Address &to, int opcode, const char* payload=nullptr, int len=0) override;
    void Recv(void) override;
#endif
};

// global engine within squid.
extern IcmpSquid icmpEngine;

#endif /* SQUID_SRC_ICMP_ICMPSQUID_H */

