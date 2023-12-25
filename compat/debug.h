/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#if defined(__GNUC__) || defined(__SUNPRO_CC)

#define debug(X...) \
                     if (debug_enabled) { \
                         fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, static_cast<long>(getpid())); \
                         fprintf(stderr,X); \
                     } else (void)0

#define ndebug(content) ndebug_(__FILE__, __LINE__, content)
#define ndebug_(file, line, content) if (debug_enabled) { \
    std::cerr << file << '(' << line << ')' << ": pid=" << getpid() << ':' \
        << content << std::endl; \
    } else (void)0

#else /* __GNUC__ || __SUNPRO_CC */

/* non-GCC compilers can't do the above macro define yet. */
void debug(const char *format,...);
#endif

#endif /* COMPAT_DEBUG_H */

