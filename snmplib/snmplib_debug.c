#include "config.h"
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#ifdef __STDC__
void (*snmplib_debug_hook) (int,char *,...) = NULL;
#else
void (*snmplib_debug_hook) (va_alist) = NULL;
#endif

extern void
#ifdef __STDC__
snmplib_debug(int lvl,char *fmt,...)
{
	va_list args;
	va_start(args, fmt);
#else
snmplib_debug(va_alist)
	va_dcl
{
	va_list args;
	int lvl;
	char char *fmt;
	va_start(args);
	lvl = va_arg(args, int);
	fmt = va_arg(args, char *);
#endif
	if (snmplib_debug_hook != NULL)
		snmplib_debug_hook(lvl, fmt, args);
	else
		vfprintf(stderr, fmt, args);
	va_end(args);
}

