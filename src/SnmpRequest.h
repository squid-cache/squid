/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMPREQUEST_H_
#define SQUID_SNMPREQUEST_H_

#if SQUID_SNMP
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

#endif /* SQUID_SNMPREQUEST_H_ */

