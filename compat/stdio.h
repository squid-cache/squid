#ifndef _SQUID_COMPAT_STDIO_H
#define _SQUID_COMPAT_STDIO_H

/** 64-bit broken <cstdio>
 *
 * <stdio.h> provides fgetpos64, fopen64 if __USE_FILE_OFFSET64 is defined.
 * It then checks whether a gcc-specific __REDIRECT macro is available
 * (defined in <sys/cdefs.h>, depending on __GNUC__ begin available).
 * If it is not available, it does a preprocessor #define.
 * Which <cstdio> undefines, with this comment:
 *   "// Get rid of those macros defined in <stdio.h>  in lieu of real functions.".
 *  When it does a namespace redirection ("namespace std { using ::fgetpos; }") it goes blam, as
 * fgetpos64 is available, while fgetpos is not.
 */

// Import the stdio.h definitions first to do the state setup
#if HAVE_STDIO_H
#include<stdio.h>
#endif

// Check for the buggy case
#if defined(__USE_FILE_OFFSET64) && !defined(__REDIRECT)

// Define the problem functions as needed
#if defined(fgetpos)
#undef fgetpos
inline int fgetpos(FILE *f, fpos64_t *p) { return fgetpos64(f,p); }
#endif
#if defined(fopen)
#undef fopen
inline FILE * fopen(const char *f, const char *m) { return fopen64(f,m); }
#endif
#if defined(freopen)
#undef freopen
inline FILE * freopen(const char *f, const char *m, FILE *s) { return freopen64(f,m,s); }
#endif
#if defined(fsetpos)
#undef fsetpos
inline int fsetpos(FILE *f, fpos64_t *p) { return fsetpos64(f,p); }
#endif
#if defined(tmpfile)
#undef tmpfile
inline FILE * tmpfile(void) { return tmpfile64(); }
#endif

#endif /* __USE_FILE_OFFSET64 && !__REDIRECT */

// Finally import the <cstdio> stuff we actually use
#if HAVE_CSTDIO && defined(__cplusplus)
#include <cstdio>
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN SQUID_MAXPATHLEN
#endif

#endif /* _SQUID_COMPAT_STDIO_H */
