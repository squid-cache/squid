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
#include "profiler/Profiler.h"
#include "util.h"

#if HAVE_STDIO_H
#include <stdio.h>
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

static void default_failure_notify(const char *);

void (*failure_notify) (const char *) = default_failure_notify;

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
        static char msg[128];
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
            static char msg[128];
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

/**
 * rounds num to the next upper integer multiple of what
 */
unsigned int RoundTo(const unsigned int num, const unsigned int what)
{
    return what * ((num + what -1)/what);
}
