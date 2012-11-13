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
#ifndef _INCLUDE_ICMPPINGER_H
#define _INCLUDE_ICMPPINGER_H
#include "Icmp.h"

/**
 * Implements the interface to squid for ICMP operations
 */
class IcmpPinger : public Icmp
{
public:
    IcmpPinger();
    virtual ~IcmpPinger();

    /// Start and initiate control channel to squid
    virtual int Open();

    /// Shutdown pinger helper and control channel
    virtual void Close();

#if USE_ICMP

    /// Send ICMP results back to squid.
    void SendResult(pingerReplyData &preply, int len);

    /// Handle ICMP requests from squid, passing to helpers.
    virtual void Recv(void);

private:
    // unused in IcmpPinger
    virtual void SendEcho(Ip::Address &to, int opcode, const char *payload, int len) {};

    /**
     * Control channel(s) to squid.
     * May be STDIN/STDOUT pipes or an IP socket depending on the OS
     */
    int socket_from_squid;
    int socket_to_squid;
#endif /* USE_ICMP */
};

#if USE_ICMP

/// pinger helper contains one of these as a global object.
extern IcmpPinger control;

#endif

#endif
