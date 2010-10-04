#include "config.h"
#include "compat/xalloc.h"
#include "compat/xstring.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

char *
xstrdup(const char *s)
{
    size_t sz;
    char *p;

    if (s == NULL) {
        if (failure_notify) {
            (*failure_notify) ("xstrdup: tried to dup a NULL pointer!\n");
        } else {
            errno = EINVAL;
            perror("xstrdup: tried to dup a NULL pointer!");
        }
        exit(1);
    }

    /* copy string, including terminating character */
    sz = strlen(s) + 1;
    p = (char *)xmalloc(sz);
    memcpy(p, s, sz);

    return p;
}

char *
xstrncpy(char *dst, const char *src, size_t n)
{
    char *r = dst;

    if (!n || !dst)
        return dst;

    if (src)
        while (--n != 0 && *src != '\0')
            *dst++ = *src++;

    *dst = '\0';
    return r;
}

char *
xstrndup(const char *s, size_t n)
{
    size_t sz;
    char *p;

    if (s == NULL) {
        errno = EINVAL;
        if (failure_notify) {
            (*failure_notify) ("xstrndup: tried to dup a NULL pointer!\n");
        } else {
            perror("xstrndup: tried to dup a NULL pointer!");
        }
        exit(1);
    }
    if (n < 0) {
        errno = EINVAL;
        if (failure_notify) {
            (*failure_notify) ("xstrndup: tried to dup a negative length string!\n");
        } else {
            perror("xstrndup: tried to dup a negative length string!");
        }
        exit(1);
    }

    sz = strlen(s) + 1;
    if (sz > n)
        sz = n;

    p = xstrncpy((char *)xmalloc(sz), s, sz);
    return p;
}
