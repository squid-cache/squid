/*
 * $Id: snmp_debug.h,v 1.11 2002/09/15 21:12:11 robertc Exp $
 */

#ifndef SQUID_SNMP_DEBUG_H
#define SQUID_SNMP_DEBUG_H

#if STDC_HEADERS
extern void 
snmplib_debug(int, const char *,...) PRINTF_FORMAT_ARG2;
#else
extern void snmplib_debug (va_alist);
#endif


#endif /* SQUID_SNMP_DEBUG_H */
