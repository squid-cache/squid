/*
 * $Id: snmp_debug.h,v 1.6 1999/01/11 21:55:34 wessels Exp $
 */

#ifndef SNMP_DEBUG_H
#define SNMP_DEBUG_H

#if STDC_HEADERS
extern void snmplib_debug(int, char *,...);
#else
extern void snmplib_debug(va_alist);
#endif

#endif
