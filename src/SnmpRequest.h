/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SNMPREQUEST_H
#define SQUID_SRC_SNMPREQUEST_H

#if SQUID_SNMP
#include "acl/forward.h"
#include "ip/Address.h"
#include "snmp_session.h"

// POD
class SnmpRequest
{
public:
    u_char *buf;
    u_char *outbuf;
    int len;
    int sock;
    long reqid;
    int outlen;

    Ip::Address from;

    struct snmp_pdu *PDU;
    ACLChecklist *acl_checklist;
    u_char *community;

    struct snmp_session session;
};

#endif /* SQUID_SNMP */

#endif /* SQUID_SRC_SNMPREQUEST_H */

