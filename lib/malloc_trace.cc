/*
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

#include "squid.h"
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

#if XMALLOC_DEBUG
#define DBG_ARRY_SZ (1<<11)
#define DBG_ARRY_BKTS (1<<8)
static void *(*malloc_ptrs)[DBG_ARRY_SZ];
static int malloc_size[DBG_ARRY_BKTS][DBG_ARRY_SZ];
static int dbg_initd = 0;

#define DBG_HASH_BUCKET(ptr)   (((((int)ptr)>>4)+(((int)ptr)>>12)+(((int)ptr)>>20))&0xFF)

static void
check_init(void)
{
    int B = 0, I = 0;
    /* calloc the ptrs so that we don't see them when hunting lost memory */
    malloc_ptrs = calloc(DBG_ARRY_BKTS, sizeof(*malloc_ptrs));

    for (B = 0; B < DBG_ARRY_BKTS; ++B) {
        for (I = 0; I < DBG_ARRY_SZ; ++I) {
            malloc_ptrs[B][I] = NULL;
            malloc_size[B][I] = 0;
        }
    }

    dbg_initd = 1;
}

static void
check_free(void *s)
{
    int B, I;
    B = DBG_HASH_BUCKET(s);

    for (I = 0; I < DBG_ARRY_SZ; ++I) {
        if (malloc_ptrs[B][I] != s)
            continue;

        malloc_ptrs[B][I] = NULL;
        malloc_size[B][I] = 0;
        break;
    }

    if (I == DBG_ARRY_SZ) {
        static char msg[128];
        snprintf(msg, 128, "xfree: ERROR: s=%p not found!", s);
        if (failure_notify)
            (*failure_notify) (msg);
        else
            perror(msg);
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

    for (I = 0; I < DBG_ARRY_SZ; ++I) {
        if (!(P = malloc_ptrs[B][I]))
            continue;

        Q = P + malloc_size[B][I];

        if (P <= p && p < Q) {
            static char msg[128];
            snprintf(msg, 128, "xmalloc: ERROR: p=%p falls in P=%p+%d",
                     p, P, malloc_size[B][I]);
            if (failure_notify)
                (*failure_notify) (msg);
            else
                perror(msg);
        }
    }

    for (I = 0; I < DBG_ARRY_SZ; ++I) {
        if (malloc_ptrs[B][I])
            continue;

        malloc_ptrs[B][I] = p;
        malloc_size[B][I] = (int) sz;
        break;
    }

    if (I == DBG_ARRY_SZ) {
        if (failure_notify)
            (*failure_notify) ("xmalloc: debug out of array space!");
        else
            perror("xmalloc: debug out of array space!");
    }
}

#endif

