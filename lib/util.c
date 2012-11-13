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
#if HAVE_MATH_H
#include <math.h>
#endif

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
