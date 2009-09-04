#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef COMPAT_DEBUG_H
#define COMPAT_DEBUG_H

/*
 * A debug method for use of external helpers and tools.
 * It shunts the debug messages down stderr for logging by Squid
 * or display to the user instead of corrupting the stdout data stream.
 */

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Debugging stuff */

/* the macro overload style is really a gcc-ism */
#ifdef __GNUC__

SQUIDCEXTERN int debug_enabled;

#define debug(X...) \
                     if (debug_enabled) { \
                         fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, (long)getpid() ); \
                         fprintf(stderr,X); \
                     }

#else /* __GNUC__ */

/* TODO: non-GCC compilers can't do the above macro define yet. */
inline void
debug(char *format,...)
{
    ; // nothing to do.
}
#endif


#endif /* COMPAT_DEBUG_H */
