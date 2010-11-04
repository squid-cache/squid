#ifndef _SQUID_COMPAT_XALLOC_H
#define _SQUID_COMPAT_XALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * xcalloc() - same as calloc(3).  Used for portability.
     * Never returns NULL; fatal on error.
     *
     * Define failure_notify to receive error message.
     * otherwise perror() is used to display it.
     */
    void *xcalloc(size_t n, size_t sz);

    /**
     * xmalloc() - same as malloc(3).  Used for portability.
     * Never returns NULL; fatal on error.
     *
     * Define failure_notify to receive error message.
     * otherwise perror() is used to display it.
     */
    void *xmalloc(size_t sz);

    /**
     * xrealloc() - same as realloc(3). Used for portability.
     * Never returns NULL; fatal on error.
     */
    void *xrealloc(void *s, size_t sz);

    /**
     *  xfree() - same as free(3).  Used for portability.
     *   Will not call free(3) if s == NULL.
     *
     * Define failure_notify to receive error message.
     * otherwise perror() is used to display it.
     */
    void xfree(void *s);

    /**
     * xxfree() / free_const() - Same as free(3).  Used for portability.
     * Accepts pointers to dynamically allocated const data.
     *
     * Define failure_notify to receive error message.
     * otherwise perror() is used to display it.
     */
    void free_const(const void *s);

/// Backward compatibility alias for free_const(const void *s)
#define xxfree(x)  free_const((x))

    /**
     * Accepts pointers to dynamically allocated const data.
     * Will not call free(3) if the pointer is NULL.
     * Sets the pointer to NULL on completion.
     *
     * Use xfree() if the pointer does not need to be set afterward.
     *
     * Define failure_notify to receive error message.
     * otherwise perror() is used to display it.
     */
#define safe_free(x)    while (x) { xxfree(x); (x) = NULL; }


#if XMALLOC_STATISTICS
    void malloc_statistics(void (*func) (int, int, int, void *), void *data);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SQUID_COMPAT_XALLOC_H */
