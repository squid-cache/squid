/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_XALLOC_H
#define SQUID_COMPAT_XALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xcalloc() - same as calloc(3).  Used for portability.
 * Never returns nullptr; fatal on error.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
void *xcalloc(size_t n, size_t sz);

/**
 * xmalloc() - same as malloc(3).  Used for portability.
 * Never returns nullptr; fatal on error.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
void *xmalloc(size_t sz);

/**
 * xrealloc() - same as realloc(3). Used for portability.
 * Never returns nullptr; fatal on error.
 */
void *xrealloc(void *s, size_t sz);

/**
 * free_const() - Same as free(3).  Used for portability.
 * Accepts pointers to dynamically allocated const data.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
void free_const(const void *s);

/**
 *  xfree() - same as free(3).  Used for portability.
 * Accepts pointers to dynamically allocated const data.
 * Will not call free(3) if the pointer is nullptr.
 *
 * Pointer is left with a value on completion.
 * Use safe_free() if the pointer needs to be set to nullptr afterward.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
static inline void xfree(const void *p) { if (p) free_const(p); }

/**
 *  safe_free() - same as free(3).  Used for portability.
 * Accepts pointers to dynamically allocated const data.
 * Will not call free(3) if the pointer is nullptr.
 * Sets the pointer to nullptr on completion.
 *
 * Use xfree() if the pointer does not need to be set afterward.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
#define safe_free(x)    while ((x)) { free_const((x)); (x) = nullptr; }

#ifdef __cplusplus
}
#endif

#if XMALLOC_STATISTICS
extern void malloc_statistics(void (*func) (int, int, int, void *), void *data);
#endif

#endif /* SQUID_COMPAT_XALLOC_H */

