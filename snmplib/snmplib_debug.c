#include "config.h"
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "snmp_debug.h"

#if STDC_HEADERS
void (*snmplib_debug_hook) (int, char *,...) = NULL;
#else
void (*snmplib_debug_hook) (va_alist) = NULL;
#endif

extern void
#if STDC_HEADERS
snmplib_debug(int lvl, const char *fmt,...)
{
    char buf[BUFSIZ];
    va_list args;
    va_start(args, fmt);
#else
snmplib_debug(va_alist)
     va_dcl
{
    va_list args;
    int lvl;
    char char *fmt;
    char buf[BUFSIZ];
    va_start(args);
    lvl = va_arg(args, int);
    fmt = va_arg(args, char *);
#endif
    if (snmplib_debug_hook != NULL) {
	vsnprintf(buf, BUFSIZ, fmt, args);
	snmplib_debug_hook(lvl, buf);
    } else {
	vfprintf(stderr, fmt, args);
    }
    va_end(args);
}
