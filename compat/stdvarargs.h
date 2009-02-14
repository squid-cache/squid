#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef _SQUID_STDVARARGS_H
#define _SQUID_STDVARARGS_H

/*
 * va_* variables come from various places on different platforms.
 * We provide a clean set of wrappers for the variosu operations
 * Depending on what is available and needed.
 */
#if defined(HAVE_STDARG_H)
#include <stdarg.h>
#define HAVE_STDARGS            /* let's hope that works everywhere (mj) */
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap, f)
#define VA_SHIFT(v,t) ;         /* no-op for ANSI */
#define VA_END va_end(ap)
#else
#if defined(HAVE_VARARGS_H)
#include <varargs.h>
#undef HAVE_STDARGS
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap)        /* f is ignored! */
#define VA_SHIFT(v,t) v = va_arg(ap,t)
#define VA_END va_end(ap)
#else
#error XX **NO VARARGS ** XX
#endif
#endif

/* Make sure syslog goes after stdarg/varargs */
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#endif /* _SQUID_STDVARARGS_H */
