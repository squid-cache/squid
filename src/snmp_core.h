/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#ifndef SQUID_SRC_SNMP_CORE_H
#define SQUID_SRC_SNMP_CORE_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "cache_snmp.h"
#include "comm/forward.h"
#include "ip/forward.h"
#include "snmp_vars.h"

class MemBuf;

#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5

typedef variable_list *(oid_ParseFn) (variable_list *, snint *);
typedef struct _mib_tree_entry mib_tree_entry;
typedef oid *(instance_Fn) (oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
typedef enum {atNone = 0, atSum, atAverage, atMax, atMin} AggrType;

struct _mib_tree_entry {
    oid *name;
    int len;
    oid_ParseFn *parsefunction;
    instance_Fn *instancefunction;
    int children;

    struct _mib_tree_entry **leaves;

    struct _mib_tree_entry *parent;
    AggrType aggrType;
};

struct snmp_pdu* snmpAgentResponse(struct snmp_pdu* PDU);
AggrType snmpAggrType(oid* Current, snint CurrentLen);

extern Comm::ConnectionPointer snmpOutgoingConn;

extern PF snmpHandleUdp;
void snmpInit(void);
void snmpOpenPorts(void);
void snmpClosePorts(void);
const char * snmpDebugOid(oid * Name, snint Len, MemBuf &outbuf);
void addr2oid(Ip::Address &addr, oid *Dest);
void oid2addr(oid *Dest, Ip::Address &addr, u_int code);

namespace Acl
{

/// an "snmp_community" ACL
class SnmpCommunityCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* Acl::Node API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_SRC_SNMP_CORE_H */

