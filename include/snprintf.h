/*
 * $Id: snprintf.h,v 1.4 1998/09/23 17:20:05 wessels Exp $
 */

/* if you have configure you can use this */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

/* varargs declarations: */
/* you might have to hand force this by doing #define HAVE_STDARG_H */

#if defined(HAVE_STDARG_H)
#include <stdarg.h>
#define HAVE_STDARGS		/* let's hope that works everywhere (mj) */
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap, f)
#define VA_SHIFT(v,t) ;		/* no-op for ANSI */
#define VA_END va_end(ap)
#else
#if defined(HAVE_VARARGS_H)
#include <varargs.h>
#undef HAVE_STDARGS
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap)	/* f is ignored! */
#define VA_SHIFT(v,t) v = va_arg(ap,t)
#define VA_END va_end(ap)
#else
XX **NO VARARGS ** XX
#endif
#endif

/* you can have ANSI C definitions */

#if !HAVE_SNPRINTF
#ifdef HAVE_STDARGS
int snprintf(char *str, size_t count, const char *fmt,...);
#else
int snprintf();
#endif
#endif

#if !HAVE_VSNPRINTF
#ifdef HAVE_STDARGS
int vsnprintf(char *str, size_t count, const char *fmt, va_list arg);
#else
int vsnprintf();
#endif
#endif
