/*
 * $Id: snmp_debug.h,v 1.13 2003/01/23 00:36:47 robertc Exp $
 */

#ifndef SQUID_SNMP_DEBUG_H
#define SQUID_SNMP_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#if STDC_HEADERS
extern void 
snmplib_debug(int, const char *,...) PRINTF_FORMAT_ARG2;
#else
extern void snmplib_debug (va_alist);
#endif

#ifdef __cplusplus
};
#endif

#endif /* SQUID_SNMP_DEBUG_H */
