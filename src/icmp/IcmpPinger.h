/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 37    ICMP Routines */

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

