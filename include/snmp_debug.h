/*
 * $Id: snmp_debug.h,v 1.7 2001/10/08 16:18:31 hno Exp $
 */

#ifndef SQUID_SNMP_DEBUG_H
#define SQUID_SNMP_DEBUG_H

#if STDC_HEADERS
extern void snmplib_debug(int, char *,...);
#else
extern void snmplib_debug(va_alist);
#endif

#endif /* SQUID_SNMP_DEBUG_H */
