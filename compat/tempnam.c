/* A reasonably functional tmpnam. */

/* Originally by Tom Hageman, tom@basil.icce.rug.nl */

/*
 * This tmpnam() was changed by Gerben_Wierda@RnA.nl to serve as
 * tempnam() for squid-1.1.6. It ignores the directory parameter, every
 * temp file is written in /tmp.
 */

#include "squid.h"
#include "compat/tempnam.h"

#if HAVE_LIBC_H
#include <libc.h>
#endif
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#undef TMP_MAX

#define _tmp		"/tmp/"
#define lengthof_tmp	5

#ifndef LONG_BIT
#define LONG_BIT	(CHAR_BIT * 4)	/* assume sizeof(long) == 4 */
#endif

#define L_tmpmin	(lengthof_tmp + 5)	/* 5 chars for pid. */

#if (L_tmpnam > L_tmpmin)
#if (L_tmpnam > L_tmpmin + LONG_BIT / 6)	/* base 64 */
#define TMP_MAX	ULONG_MAX
#else
#define TMP_MAX	((1L << (6 * (L_tmpnam - L_tmpmin))) - 1)
#endif
#else
#ifndef L_tmpnam
#error "tmpnam: L_tmpnam undefined"
#else
#error "tmpnam: L_tmpnam too small"
#endif
#endif

static char *
_tmpnam(void)
{
    static const char digits[] =
#if (L_tmpnam >= L_tmpmin + LONG_BIT / 4)
        "0123456789abcdef";
#define TMP_BASE	16
#else
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
#define TMP_BASE	64
#endif
    static unsigned long lastcount = 0;
    static char buffer[L_tmpnam + 1];
    char *s = buffer;
    unsigned long count = lastcount;
    pid_t pid = getpid();

    if (sizeof(_tmp) - 1 != lengthof_tmp)
        abort();		/* Consistency error. */

    for (;;) {
        register int i = L_tmpnam;
        register unsigned long c;
        register unsigned int p;

        /* Build filename. (the hard way) */
        s += i;
        *s = '\0';

        c = (count == TMP_MAX) ? 0 : ++count;
        do {
            *--s = digits[c % TMP_BASE];
            c /= TMP_BASE;
        } while (--i > L_tmpmin);

        p = (unsigned int) pid;
        do {
            *--s = digits[p % 10];
            p /= 10;
        } while (--i > lengthof_tmp);

        do {
            *--s = _tmp[--i];
        } while (i > 0);

        /* Check that the file doesn't exist. */
        if (access(s, 0) != 0)
            break;

        /* It exists; retry unless we tried them all. */
        if (count == lastcount) {
            s = NULL;
            break;
        }
    }

    lastcount = count;

    return s;
}

char *
tempnam(const char *dir, const char *pfx)
{
    return _tmpnam();
}

#ifdef TEST
int
main()
{
    char *t;
    int n = 0;
    while ((t = tempnam(NULL, NULL))) {
        printf("%s\n", t);
        if (++n == 1000)
            break;
    }
    return 1;
}
#endif
