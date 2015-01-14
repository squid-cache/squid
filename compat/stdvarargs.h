/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_STDVARARGS_H
#define _SQUID_STDVARARGS_H

/*
 * va_* variables come from various places on different platforms.
 * We provide a clean set of wrappers for the various operations
 * Depending on what is available and needed.
 */
#if defined(__cplusplus)
#include <cstdarg>

#else
#if HAVE_STDARG_H
#include <stdarg.h>
#define HAVE_STDARGS            /* let's hope that works everywhere (mj) */
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap, f)
#define VA_SHIFT(v,t) ;         /* no-op for ANSI */
#define VA_END va_end(ap)

#else /* !HAVE_STDARG_H */
#if HAVE_VARARGS_H
#include <varargs.h>
#undef HAVE_STDARGS
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap)        /* f is ignored! */
#define VA_SHIFT(v,t) v = va_arg(ap,t)
#define VA_END va_end(ap)

#else /* !HAVE_VARARGS_H*/
#error XX **NO VARARGS ** XX
#endif /* HAVE_VARARGS_H */
#endif /* HAVE_STDARG_H */
#endif /* HAVE_CSTDARG */

/* Make sure syslog goes after stdarg/varargs */
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif

#endif /* _SQUID_STDVARARGS_H */

