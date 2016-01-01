/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef COMPAT_DEBUG_H
#define COMPAT_DEBUG_H

/*
 * A debug method for use of external helpers and tools.
 * It shunts the debug messages down stderr for logging by Squid
 * or display to the user instead of corrupting the stdout data stream.
 */
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Debugging stuff */

SQUIDCEXTERN int debug_enabled;

/* the macro overload style is really a gcc-ism */
#ifdef __GNUC__

#define debug(X...) \
                     if (debug_enabled) { \
                         fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, (long)getpid() ); \
                         fprintf(stderr,X); \
                     } else (void)0

#else /* __GNUC__ */

/* non-GCC compilers can't do the above macro define yet. */
void debug(const char *format,...);
#endif

#endif /* COMPAT_DEBUG_H */

