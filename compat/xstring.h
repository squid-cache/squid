/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_XSTRING_H
#define SQUID_COMPAT_XSTRING_H

#if HAVE_STRING_H
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xstrdup() - same as strdup(3).  Used for portability.
 * Never returns NULL; fatal on error.
 *
 * Sets errno to EINVAL if a NULL pointer is passed.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
char *xstrdup(const char *s);

#ifdef strdup
#undef strdup
#endif
#define strdup(X) xstrdup((X))

/*
 *  xstrncpy() - similar to strncpy(3) but terminates string
 *  always with '\0' if (n != 0 and dst != NULL),
 *  and doesn't do padding
 */
char *xstrncpy(char *dst, const char *src, size_t n);

/**
 * xstrndup() - Somewhat similar(XXX) to strndup(3): Allocates up to n bytes,
 * while strndup(3) copies up to n bytes and allocates up to n+1 bytes
 * to fit the terminating character. Assumes s is 0-terminated (another XXX).
 *
 * Never returns NULL; fatal on error.
 *
 * Sets errno to EINVAL if a NULL pointer or negative
 * length is passed.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
char *xstrndup(const char *s, size_t n);

#ifdef strndup
#undef strndup
#endif
#define strndup(X) xstrndup((X))

#ifdef __cplusplus
}
#endif

#endif /* SQUID_COMPAT_XSTRING_H */

