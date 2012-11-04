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
