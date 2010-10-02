#ifndef _SQUID_SNMP_CORE_H
#define _SQUID_SNMP_CORE_H

#include "config.h"

#if SQUID_SNMP
#include "comm/forward.h"

extern Comm::ConnectionPointer snmpOutgoingConn;
// PRIVATE? extern int theInSnmpConnection;
// DEAD? extern char *snmp_agentinfo;

#endif /* SQUID_SNMP */

#endif /* _SQUID_SNMP_CORE_H */
