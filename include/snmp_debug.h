/*
 * $Id: snmp_debug.h,v 1.5 1998/09/23 17:20:02 wessels Exp $
 */

#ifndef SNMP_DEBUG_H
#define SNMP_DEBUG_H

#ifdef __STDC__
extern void snmplib_debug(int, char *,...);
#else
extern void snmplib_debug(va_alist);
#endif

#endif
