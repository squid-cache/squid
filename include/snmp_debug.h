/*
 * $Id: snmp_debug.h,v 1.9 2001/10/22 23:55:43 hno Exp $
 */

#ifndef SQUID_SNMP_DEBUG_H
#define SQUID_SNMP_DEBUG_H

extern void 
snmplib_debug(int, const char *,...) PRINTF_FORMAT_ARG(2);

#endif /* SQUID_SNMP_DEBUG_H */
