/*
 * $Id: snmp_debug.h,v 1.12 2002/10/13 20:34:51 robertc Exp $
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
