/*
 * $Id$
 *
 * DEBUG: section 49    SNMP Interface
 *
 */

#ifndef SQUID_SNMP_CORE_H
#define SQUID_SNMP_CORE_H

#include "config.h"
#include "cache_snmp.h"

#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5


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

extern struct snmp_pdu* snmpAgentResponse(struct snmp_pdu* PDU);
extern AggrType snmpAggrType(oid* Current, snint CurrentLen);

#endif /* SQUID_SNMP_CORE_H */
