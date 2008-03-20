/*
 * $Id: snmp_debug.h,v 1.13 2003/01/23 00:36:47 robertc Exp $
 */
#ifndef SQUID_SNMP_DEBUG_H
#define SQUID_SNMP_DEBUG_H

#include "config.h"

#if STDC_HEADERS
SQUIDCEXTERN void snmplib_debug(int, const char *,...) PRINTF_FORMAT_ARG2;
#else
SQUIDCEXTERN void snmplib_debug(va_alist);
#endif

#endif /* SQUID_SNMP_DEBUG_H */
