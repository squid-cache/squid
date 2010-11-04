#include "config.h"
#include "compat/xstrerror.h"

#if HAVE_STRING_H
#include <string.h>
#endif

const char *
xstrerr(int error)
{
    static char xstrerror_buf[BUFSIZ];
    const char *errmsg = strerror(error);

    if (!errmsg || !*errmsg)
        errmsg = "Unknown error";

    snprintf(xstrerror_buf, BUFSIZ, "(%d) %s", error, errmsg);

    return xstrerror_buf;
}
