/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 37    ICMP Routines */

#ifndef _INCLUDE_ICMPSQUID_H
#define _INCLUDE_ICMPSQUID_H

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
    virtual ~IcmpSquid();

    virtual int Open();
    virtual void Close();

    void DomainPing(Ip::Address &to, const char *domain);

#if USE_ICMP
    virtual void SendEcho(Ip::Address &to, int opcode, const char* payload=NULL, int len=0);
    virtual void Recv(void);
#endif
};

// global engine within squid.
extern IcmpSquid icmpEngine;

#endif /* _INCLUDE_ICMPSQUID_H */

