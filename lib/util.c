
/*
 * $Id$
 *
 * DEBUG:
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#define _etext etext

#include "config.h"
#include "profiling.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_GNUMALLLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_MATH_H
#include <math.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "util.h"

static void default_failure_notify(const char *);

void (*failure_notify) (const char *) = default_failure_notify;
static char msg[128];

#if MEM_GEN_TRACE

static FILE *tracefp = NULL;

void
log_trace_init(char *fn)
{
    tracefp = fopen(fn, "a+");

    if (!tracefp) {
        perror("log_trace_init");
        exit(1);
    }
}

void
log_trace_done()
{
    fclose(tracefp);
    tracefp = NULL;
}

#endif

#if XMALLOC_STATISTICS
#define DBG_MAXSIZE   (1024*1024)
#define DBG_SPLIT     (256)	/* mallocs below this value are tracked with DBG_GRAIN_SM precision instead of DBG_GRAIN */
#define DBG_GRAIN     (16)
#define DBG_GRAIN_SM  (4)
#define DBG_OFFSET    (DBG_SPLIT/DBG_GRAIN_SM - DBG_SPLIT/DBG_GRAIN )
#define DBG_MAXINDEX  (DBG_MAXSIZE/DBG_GRAIN + DBG_OFFSET)
// #define DBG_INDEX(sz) (sz<DBG_MAXSIZE?(sz+DBG_GRAIN-1)/DBG_GRAIN:DBG_MAXINDEX)
static int malloc_sizes[DBG_MAXINDEX + 1];
static int malloc_histo[DBG_MAXINDEX + 1];
static int dbg_stat_init = 0;

static int
DBG_INDEX(int sz)
{
    if (sz >= DBG_MAXSIZE)
        return DBG_MAXINDEX;

    if (sz <= DBG_SPLIT)
        return (sz + DBG_GRAIN_SM - 1) / DBG_GRAIN_SM;

    return (sz + DBG_GRAIN - 1) / DBG_GRAIN + DBG_OFFSET;
}

static void
stat_init(void)
{
    int i;

    for (i = 0; i <= DBG_MAXINDEX; i++)
        malloc_sizes[i] = malloc_histo[i] = 0;

    dbg_stat_init = 1;
}

static int
malloc_stat(int sz)
{
    if (!dbg_stat_init)
        stat_init();

    return malloc_sizes[DBG_INDEX(sz)] += 1;
}

void
malloc_statistics(void (*func) (int, int, int, void *), void *data)
{
    int i;

    for (i = 0; i <= DBG_SPLIT; i += DBG_GRAIN_SM)
        func(i, malloc_sizes[DBG_INDEX(i)], malloc_histo[DBG_INDEX(i)], data);

    i -= DBG_GRAIN_SM;

    for (i = i; i <= DBG_MAXSIZE; i += DBG_GRAIN)
        func(i, malloc_sizes[DBG_INDEX(i)], malloc_histo[DBG_INDEX(i)], data);

    xmemcpy(&malloc_histo, &malloc_sizes, sizeof(malloc_sizes));
}

#endif /* XMALLOC_STATISTICS */



#if XMALLOC_TRACE
char *xmalloc_file = "";
int xmalloc_line = 0;
char *xmalloc_func = "";
static int xmalloc_count = 0;
int xmalloc_trace = 0;		/* Enable with -m option */
size_t xmalloc_total = 0;
#undef xmalloc
#undef xfree
#undef xxfree
#undef xrealloc
#undef xcalloc
#undef xstrdup
#endif

#if XMALLOC_DEBUG
#define DBG_ARRY_SZ (1<<11)
#define DBG_ARRY_BKTS (1<<8)
static void *(*malloc_ptrs)[DBG_ARRY_SZ];
static int malloc_size[DBG_ARRY_BKTS][DBG_ARRY_SZ];
#if XMALLOC_TRACE
static char *malloc_file[DBG_ARRY_BKTS][DBG_ARRY_SZ];
static short malloc_line[DBG_ARRY_BKTS][DBG_ARRY_SZ];
static int malloc_count[DBG_ARRY_BKTS][DBG_ARRY_SZ];
#endif
static int dbg_initd = 0;

#define DBG_HASH_BUCKET(ptr)   (((((int)ptr)>>4)+(((int)ptr)>>12)+(((int)ptr)>>20))&0xFF)

static void
check_init(void)
{
    int B = 0, I = 0;
    /* calloc the ptrs so that we don't see them when hunting lost memory */
    malloc_ptrs = calloc(DBG_ARRY_BKTS, sizeof(*malloc_ptrs));

    for (B = 0; B < DBG_ARRY_BKTS; B++) {
        for (I = 0; I < DBG_ARRY_SZ; I++) {
            malloc_ptrs[B][I] = NULL;
            malloc_size[B][I] = 0;
#if XMALLOC_TRACE

            malloc_file[B][I] = NULL;
            malloc_line[B][I] = 0;
            malloc_count[B][I] = 0;
#endif

        }
    }

    dbg_initd = 1;
}

static void
check_free(void *s)
{
    int B, I;
    B = DBG_HASH_BUCKET(s);

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (malloc_ptrs[B][I] != s)
            continue;

        malloc_ptrs[B][I] = NULL;

        malloc_size[B][I] = 0;

#if XMALLOC_TRACE

        malloc_file[B][I] = NULL;

        malloc_line[B][I] = 0;

        malloc_count[B][I] = 0;

#endif

        break;
    }

    if (I == DBG_ARRY_SZ) {
        snprintf(msg, 128, "xfree: ERROR: s=%p not found!", s);
        (*failure_notify) (msg);
    }
}

static void
check_malloc(void *p, size_t sz)
{
    void *P, *Q;
    int B, I;

    if (!dbg_initd)
        check_init();

    B = DBG_HASH_BUCKET(p);

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (!(P = malloc_ptrs[B][I]))
            continue;

        Q = P + malloc_size[B][I];

        if (P <= p && p < Q) {
            snprintf(msg, 128, "xmalloc: ERROR: p=%p falls in P=%p+%d",
                     p, P, malloc_size[B][I]);
            (*failure_notify) (msg);
        }
    }

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (malloc_ptrs[B][I])
            continue;

        malloc_ptrs[B][I] = p;

        malloc_size[B][I] = (int) sz;

#if XMALLOC_TRACE

        malloc_file[B][I] = xmalloc_file;

        malloc_line[B][I] = xmalloc_line;

        malloc_count[B][I] = xmalloc_count;

#endif

        break;
    }

    if (I == DBG_ARRY_SZ)
        (*failure_notify) ("xmalloc: debug out of array space!");
}

#endif

#if XMALLOC_TRACE && !HAVE_MALLOCBLKSIZE
size_t
xmallocblksize(void *p)
{
    int B, I;
    B = DBG_HASH_BUCKET(p);

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (malloc_ptrs[B][I] == p)
            return malloc_size[B][I];
    }

    return 0;
}

#endif

#ifdef XMALLOC_TRACE
static char *
malloc_file_name(void *p)
{
    int B, I;
    B = DBG_HASH_BUCKET(p);

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (malloc_ptrs[B][I] == p)
            return malloc_file[B][I];
    }

    return 0;
}

int
malloc_line_number(void *p)
{
    int B, I;
    B = DBG_HASH_BUCKET(p);

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (malloc_ptrs[B][I] == p)
            return malloc_line[B][I];
    }

    return 0;
}

int
malloc_number(void *p)
{
    int B, I;
    B = DBG_HASH_BUCKET(p);

    for (I = 0; I < DBG_ARRY_SZ; I++) {
        if (malloc_ptrs[B][I] == p)
            return malloc_count[B][I];
    }

    return 0;
}

static void
xmalloc_show_trace(void *p, int sign)
{
    int statMemoryAccounted();
    static size_t last_total = 0, last_accounted = 0, last_mallinfo = 0;
    size_t accounted = statMemoryAccounted();
    size_t mi = 0;
    size_t sz;
#if HAVE_MALLINFO

    struct mallinfo mp = mallinfo();
    mi = mp.uordblks + mp.usmblks + mp.hblkhd;
#endif

    sz = xmallocblksize(p) * sign;
    xmalloc_total += sz;
    xmalloc_count += sign > 0;

    if (xmalloc_trace) {
        fprintf(stderr, "%c%8p size=%5d/%d acc=%5d/%d mallinfo=%5d/%d %s:%d %s",
                sign > 0 ? '+' : '-', p,
                (int) xmalloc_total - last_total, (int) xmalloc_total,
                (int) accounted - last_accounted, (int) accounted,
                (int) mi - last_mallinfo, (int) mi,
                xmalloc_file, xmalloc_line, xmalloc_func);

        if (sign < 0)
            fprintf(stderr, " (%d %s:%d)\n", malloc_number(p), malloc_file_name(p), malloc_line_number(p));
        else
            fprintf(stderr, " %d\n", xmalloc_count);
    }

    last_total = xmalloc_total;
    last_accounted = accounted;
    last_mallinfo = mi;
}

short malloc_refs[DBG_ARRY_BKTS][DBG_ARRY_SZ];
#define XMALLOC_LEAK_ALIGN (4)
static void
xmalloc_scan_region(void *start, int size, int depth)
{
    int B, I;
    char *ptr = start;
    char *end = ptr + size - XMALLOC_LEAK_ALIGN;
    static int sum = 0;

    while (ptr <= end) {
        void *p = *(void **) ptr;

        if (p && p != start) {
            B = DBG_HASH_BUCKET(p);

            for (I = 0; I < DBG_ARRY_SZ; I++) {
                if (malloc_ptrs[B][I] == p) {
                    if (!malloc_refs[B][I]++) {
                        /* A new reference */
                        fprintf(stderr, "%*s%p %s:%d size %d allocation %d\n",
                                depth, "",
                                malloc_ptrs[B][I], malloc_file[B][I],
                                malloc_line[B][I], malloc_size[B][I],
                                malloc_count[B][I]);
                        sum += malloc_size[B][I];
                        xmalloc_scan_region(malloc_ptrs[B][I], malloc_size[B][I], depth + 1);

                        if (depth == 0) {
                            if (sum != malloc_size[B][I])
                                fprintf(stderr, "=== %d bytes\n", sum);

                            sum = 0;
                        }

#if XMALLOC_SHOW_ALL_REFERENCES

                    } else {
                        /* We have already scanned this pointer... */
                        fprintf(stderr, "%*s%p %s:%d size %d allocation %d ... (%d)\n",
                                depth * 2, "",
                                malloc_ptrs[B][I], malloc_file[B][I],
                                malloc_line[B][I], malloc_size[B][I],
                                malloc_count[B][I], malloc_refs[B][I]);
#endif

                    }
                }
            }
        }

        ptr += XMALLOC_LEAK_ALIGN;
    }
}

void
xmalloc_find_leaks(void)
{
    int B, I;
    int leak_sum = 0;

    extern void _etext;
    fprintf(stderr, "----- Memory map ----\n");
    xmalloc_scan_region(&_etext, (void *) sbrk(0) - (void *) &_etext, 0);

    for (B = 0; B < DBG_ARRY_BKTS; B++) {
        for (I = 0; I < DBG_ARRY_SZ; I++) {
            if (malloc_ptrs[B][I] && malloc_refs[B][I] == 0) {
                /* Found a leak... */
                fprintf(stderr, "Leak found: %p", malloc_ptrs[B][I]);
                fprintf(stderr, " %s", malloc_file[B][I]);
                fprintf(stderr, ":%d", malloc_line[B][I]);
                fprintf(stderr, " size %d", malloc_size[B][I]);
                fprintf(stderr, " allocation %d\n", malloc_count[B][I]);
                leak_sum += malloc_size[B][I];
            }
        }
    }

    if (leak_sum) {
        fprintf(stderr, "Total leaked memory: %d\n", leak_sum);
    } else {
        fprintf(stderr, "No memory leaks detected\n");
    }

    fprintf(stderr, "----------------------\n");
}

#endif /* XMALLOC_TRACE */

/*
 *  xmalloc() - same as malloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *
xmalloc(size_t sz)
{
    void *p;

    PROF_start(xmalloc);

    if (sz < 1)
        sz = 1;

    PROF_start(malloc);

    p = malloc(sz);

    PROF_stop(malloc);

    if (p == NULL) {
        if (failure_notify) {
            snprintf(msg, 128, "xmalloc: Unable to allocate %d bytes!\n",
                     (int) sz);
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

    PROF_stop(xmalloc);

    return (p);
}

/*
 *  xfree() - same as free(3).  Will not call free(3) if s == NULL.
 */
void
xfree(void *s)
{
    PROF_start(xfree);
#if XMALLOC_TRACE

    xmalloc_show_trace(s, -1);
#endif

#if XMALLOC_DEBUG

    if (s != NULL)
        check_free(s);

#endif

    if (s != NULL)
        free(s);

#if MEM_GEN_TRACE

    if (tracefp && s)
        fprintf(tracefp, "f:%p\n", s);

#endif

    PROF_stop(xfree);
}

/* xxfree() - like xfree(), but we already know s != NULL */
void
xxfree(const void *s_const)
{
    void *s = (void *) s_const;
    PROF_start(xxfree);
#if XMALLOC_TRACE

    xmalloc_show_trace(s, -1);
#endif
#if XMALLOC_DEBUG

    check_free(s);
#endif

    free(s);
#if MEM_GEN_TRACE

    if (tracefp && s)
        fprintf(tracefp, "f:%p\n", s);

#endif

    PROF_stop(xxfree);
}

/*
 *  xrealloc() - same as realloc(3). Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *
xrealloc(void *s, size_t sz)
{
    void *p;

    PROF_start(xrealloc);
#if XMALLOC_TRACE

    xmalloc_show_trace(s, -1);
#endif

    if (sz < 1)
        sz = 1;

#if XMALLOC_DEBUG

    if (s != NULL)
        check_free(s);

#endif

    if ((p = realloc(s, sz)) == NULL) {
        if (failure_notify) {
            snprintf(msg, 128, "xrealloc: Unable to reallocate %d bytes!\n",
                     (int) sz);
            (*failure_notify) (msg);
        } else {
            perror("realloc");
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

    if (tracefp)		/* new ptr, old ptr, new size */
        fprintf(tracefp, "r:%p:%p:%d\n", p, s, sz);

#endif

    PROF_stop(xrealloc);

    return (p);
}

/*
 *  xcalloc() - same as calloc(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
void *
xcalloc(size_t n, size_t sz)
{
    void *p;

    PROF_start(xcalloc);

    if (n < 1)
        n = 1;

    if (sz < 1)
        sz = 1;

    PROF_start(calloc);

    p = calloc(n, sz);

    PROF_stop(calloc);

    if (p == NULL) {
        if (failure_notify) {
            snprintf(msg, 128, "xcalloc: Unable to allocate %u blocks of %u bytes!\n",
                     (unsigned int) n, (unsigned int) sz);
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

    PROF_stop(xcalloc);

    return (p);
}

/*
 *  xstrdup() - same as strdup(3).  Used for portability.
 *  Never returns NULL; fatal on error.
 */
char *
xstrdup(const char *s)
{
    size_t sz;
    char *p;
    PROF_start(xstrdup);

    if (s == NULL) {
        if (failure_notify) {
            (*failure_notify) ("xstrdup: tried to dup a NULL pointer!\n");
        } else {
            fprintf(stderr, "xstrdup: tried to dup a NULL pointer!\n");
        }

        exit(1);
    }

    /* copy string, including terminating character */
    sz = strlen(s) + 1;

    p = (char *)xmalloc(sz);
    memcpy(p, s, sz);

    PROF_stop(xstrdup);

    return p;
}

/*
 *  xstrndup() - string dup with length limit.
 */
char *
xstrndup(const char *s, size_t n)
{
    size_t sz;
    char *p;
    PROF_start(xstrndup);
    assert(s != NULL);
    assert(n);
    sz = strlen(s) + 1;

    if (sz > n)
        sz = n;

    p = xstrncpy((char *)xmalloc(sz), s, sz);

    PROF_stop(xstrndup);

    return p;
}

/*
 * xstrerror() - strerror() wrapper
 */
const char *
xstrerr(int error)
{
    static char xstrerror_buf[BUFSIZ];
    const char *errmsg;

    errmsg = strerror(error);

    if (!errmsg || !*errmsg)
        errmsg = "Unknown error";

    snprintf(xstrerror_buf, BUFSIZ, "(%d) %s", error, errmsg);

    return xstrerror_buf;
}

const char *
xstrerror(void)
{
    return xstrerr(errno);
}

void
Tolower(char *q)
{
    char *s = q;

    while (*s) {
        *s = xtolower(*s);
        s++;
    }
}

int

tvSubMsec(struct timeval t1, struct timeval t2)
{
    return (t2.tv_sec - t1.tv_sec) * 1000 +
           (t2.tv_usec - t1.tv_usec) / 1000;
}

int

tvSubUsec(struct timeval t1, struct timeval t2)
{
    return (t2.tv_sec - t1.tv_sec) * 1000000 +
           (t2.tv_usec - t1.tv_usec);
}

double

tvSubDsec(struct timeval t1, struct timeval t2)
{
    return (double) (t2.tv_sec - t1.tv_sec) +
           (double) (t2.tv_usec - t1.tv_usec) / 1000000.0;
}

/*
 *  xstrncpy() - similar to strncpy(3) but terminates string
 *  always with '\0' if (n != 0 and dst != NULL),
 *  and doesn't do padding
 */
char *
xstrncpy(char *dst, const char *src, size_t n)
{
    char *r = dst;
    PROF_start(xstrncpy);

    if (!n || !dst)
        return dst;

    if (src)
        while (--n != 0 && *src != '\0')
            *dst++ = *src++;

    *dst = '\0';

    PROF_stop(xstrncpy);

    return r;
}

/* returns the number of leading white spaces in str; handy in skipping ws */
size_t
xcountws(const char *str)
{
    size_t count = 0;
    PROF_start(xcountws);

    if (str) {
        while (xisspace(*str)) {
            str++;
            count++;
        }
    }

    PROF_stop(xcountws);
    return count;
}

/* somewhat safer calculation of %s */
double
xpercent(double part, double whole)
{
    return xdiv(100 * part, whole);
}

int
xpercentInt(double part, double whole)
{
#if HAVE_RINT
    return (int) rint(xpercent(part, whole));
#else
    /* SCO 3.2v4.2 doesn't have rint() -- mauri@mbp.ee */
    return (int) floor(xpercent(part, whole) + 0.5);
#endif
}

/* somewhat safer division */
double
xdiv(double nom, double denom)
{
    return (denom != 0.0) ? nom / denom : -1.0;
}

/* integer to string */
const char *
xitoa(int num)
{
    static char buf[24];	/* 2^64 = 18446744073709551616 */
    snprintf(buf, sizeof(buf), "%d", num);
    return buf;
}

/* int64_t to string */
const char *
xint64toa(int64_t num)
{
    static char buf[24];	/* 2^64 = 18446744073709551616 */
    snprintf(buf, sizeof(buf), "%" PRId64, num);
    return buf;
}

/* A default failure notifier when the main program hasn't installed any */
void
default_failure_notify(const char *message)
{
    if (write(2, message, strlen(message))) {}
    if (write(2, "\n", 1)) {}
    abort();
}

void
gb_flush(gb_t * g)
{
    g->gb += (g->bytes >> 30);
    g->bytes &= (1 << 30) - 1;
}

double
gb_to_double(const gb_t * g)
{
    return ((double) g->gb) * ((double) (1 << 30)) + ((double) g->bytes);
}

const char *
double_to_str(char *buf, int buf_size, double value)
{
    /* select format */

    if (value < 1e9)
        snprintf(buf, buf_size, "%.2f MB", value / 1e6);
    else if (value < 1e12)
        snprintf(buf, buf_size, "%.3f GB", value / 1e9);
    else
        snprintf(buf, buf_size, "%.4f TB", value / 1e12);

    return buf;
}

const char *
gb_to_str(const gb_t * g)
{
    /*
     * it is often convenient to call gb_to_str several times for _one_ printf
     */
#define max_cc_calls 5
    typedef char GbBuf[32];
    static GbBuf bufs[max_cc_calls];
    static int call_id = 0;
    double value = gb_to_double(g);
    char *buf = bufs[call_id++];

    if (call_id >= max_cc_calls)
        call_id = 0;

    /* select format */
    if (value < 1e9)
        snprintf(buf, sizeof(GbBuf), "%.2f MB", value / 1e6);
    else if (value < 1e12)
        snprintf(buf, sizeof(GbBuf), "%.2f GB", value / 1e9);
    else
        snprintf(buf, sizeof(GbBuf), "%.2f TB", value / 1e12);

    return buf;
}
