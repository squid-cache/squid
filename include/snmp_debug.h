#ifndef SNMP_DEBUG_H
#define SNMP_DEBUG_H

#ifdef __STDC__
extern void snmplib_debug(int,char *,...);
#else
extern void snmplib_debug(va_alist);
#endif

#endif

