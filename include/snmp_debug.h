#ifndef SNMP_DEBUG_H
#define SNMP_DEBUG_H

#ifndef SQUID_H
#ifdef __STDC__
extern void snmplib_debug(int,char *,...);
extern void (*snmplib_debug_hook) (int,char *,...);
#else
extern void snmplib_debug(va_alist);
extern void (*snmplib_debug_hook) (va_alist);
#endif

#endif

#endif

