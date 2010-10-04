#ifndef _SQUID_COMPAT_XALLOC_H
#define _SQUID_COMPAT_XALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  xcalloc() - same as calloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
void *xcalloc(size_t n, size_t sz);

/**
 *  xmalloc() - same as malloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
void *xmalloc(size_t sz);

/**
 *  xfree() - same as free(3).  Used for portability.
 *   Will not call free(3) if s == NULL.
 *
 * Define failure_notify to receive error message.
 * otherwise perror() is used to display it.
 */
void xfree(void *s);

#ifdef __cplusplus
}
#endif

#endif /* _SQUID_COMPAT_XALLOC_H */
