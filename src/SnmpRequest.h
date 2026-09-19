/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SNMPREQUEST_H
#define SQUID_SRC_SNMPREQUEST_H

#if SQUID_SNMP

#include "acl/forward.h"
#include "compat/netsnmp.h"
#include "ip/Address.h"

// POD
class SnmpRequest
{
public:
    u_char *buf = nullptr;
    u_char *outbuf = nullptr;
    int len = 0;
    int sock = -1;
    long reqid = 0;
    int outlen = 0;

    Ip::Address from;

    struct snmp_pdu *PDU = nullptr;
    u_char *community = nullptr; // TODO: can we use PDU->community instead?

    struct snmp_session session;
};

#endif /* SQUID_SNMP */

#endif /* SQUID_SRC_SNMPREQUEST_H */

