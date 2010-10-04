#include "config.h"
#include "compat/xalloc.h"

void *
xcalloc(size_t n, size_t sz)
{
    void *p;

    if (n < 1)
        n = 1;

    if (sz < 1)
        sz = 1;

    p = calloc(n, sz);

    if (p == NULL) {
        if (failure_notify) {
            static char msg[128];
            snprintf(msg, 128, "xcalloc: Unable to allocate %u blocks of %u bytes!\n",
                     (unsigned int) n, (unsigned int) sz);
            msg[127] = '\0';
            (*failure_notify) (msg);
        } else {
            perror("xcalloc");
        }
        exit(1);
    }

#if XMALLOC_DEBUG
    check_malloc(p, sz * n);
#endif
#if XMALLOC_STATISTICS
    malloc_stat(sz * n);
#endif
#if XMALLOC_TRACE
    xmalloc_show_trace(p, 1);
#endif
#if MEM_GEN_TRACE
    if (tracefp)
        fprintf(tracefp, "c:%u:%u:%p\n", (unsigned int) n, (unsigned int) sz, p);
#endif

    return p;
}

void *
xmalloc(size_t sz)
{
    void *p;

    if (sz < 1)
        sz = 1;

    p = malloc(sz);

    if (p == NULL) {
        if (failure_notify) {
            static char msg[128];
            snprintf(msg, 128, "xmalloc: Unable to allocate %d bytes!\n",
                     (int) sz);
            msg[127] = '\0';
            (*failure_notify) (msg);
        } else {
            perror("malloc");
        }
        exit(1);
    }

#if XMALLOC_DEBUG
    check_malloc(p, sz);
#endif
#if XMALLOC_STATISTICS
    malloc_stat(sz);
#endif
#if XMALLOC_TRACE
    xmalloc_show_trace(p, 1);
#endif
#if MEM_GEN_TRACE
    if (tracefp)
        fprintf(tracefp, "m:%d:%p\n", sz, p);
#endif

    return (p);
}

void
xfree(void *s)
{
#if XMALLOC_TRACE
    xmalloc_show_trace(s, -1);
#endif

    if (s != NULL) {
#if XMALLOC_DEBUG
        check_free(s);
#endif
        free(s);
    }

#if MEM_GEN_TRACE
    if (tracefp && s)
        fprintf(tracefp, "f:%p\n", s);
#endif
}
