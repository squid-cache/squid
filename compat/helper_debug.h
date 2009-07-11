#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef COMPAT_HELPER_DEBUG_H
#define COMPAT_HELPER_DEBUG_H

/*
 * A debug method for use of external helpers.
 * It shunts the debug messages down stderr for logging by Squid
 * of display to the user instead of corrupting the stdout data stream.
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

#define helper_debug(X...) \
                     if (debug_enabled) { \
                         fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, (long)getpid() ); \
                         fprintf(stderr,X); \
                     }

#else /* __GNUC__ */

/* TODO: non-GCC compilers can't do the above macro define yet. */
inline void
helper_debug(char *format,...)
{
    ; // nothing to do.
}
#endif


#endif /* COMPAT_HELPER_DEBUG_H */
