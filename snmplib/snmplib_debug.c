#include "squid.h"
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <stdarg.h>

#include "snmp_debug.h"

void (*snmplib_debug_hook) (int, char *,...) = NULL;

extern void
snmplib_debug(int lvl, const char *fmt,...)
{
    char buf[BUFSIZ];
    va_list args;
    va_start(args, fmt);

    if (snmplib_debug_hook != NULL) {
        vsnprintf(buf, BUFSIZ, fmt, args);
        snmplib_debug_hook(lvl, buf);
    } else {
        vfprintf(stderr, fmt, args);
    }
    va_end(args);
}
