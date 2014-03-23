/*
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

#ifndef SQUID_UTIL_H
#define SQUID_UTIL_H

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

SQUIDCEXTERN int tvSubUsec(struct timeval, struct timeval);
SQUIDCEXTERN double tvSubDsec(struct timeval, struct timeval);
SQUIDCEXTERN void Tolower(char *);
#if defined(__cplusplus)
/*
 * Any code using libstdc++ must have externally resolvable overloads
 * for void * operator new - which means in the .o for the binary,
 * or in a shared library. static libs don't propogate the symbol
 * so, look in the translation unit containing main() in squid
 * for the extern version in squid
 */
#if !defined(_SQUID_EXTERNNEW_)
#if defined(__GNUC_STDC_INLINE__) || defined(__GNUC_GNU_INLINE__)
#define _SQUID_EXTERNNEW_ extern inline __attribute__((gnu_inline))
#else
#define _SQUID_EXTERNNEW_ extern inline
#endif
#endif
#include "SquidNew.h"
#endif

SQUIDCEXTERN time_t parse_iso3307_time(const char *buf);

SQUIDCEXTERN double xpercent(double part, double whole);
SQUIDCEXTERN int xpercentInt(double part, double whole);
SQUIDCEXTERN double xdiv(double nom, double denom);

SQUIDCEXTERN const char *xitoa(int num);
SQUIDCEXTERN const char *xint64toa(int64_t num);

typedef struct {
    size_t count;
    size_t bytes;
    size_t gb;
} gb_t;

/* gb_type operations */
#define gb_flush_limit (0x3FFFFFFF)
#define gb_inc(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->bytes += delta; (gb)->count++; }
#define gb_incb(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->bytes += delta; }
#define gb_incc(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->count+= delta; }
extern double gb_to_double(const gb_t *);
SQUIDCEXTERN const char *double_to_str(char *buf, int buf_size, double value);
extern const char *gb_to_str(const gb_t *);
extern void gb_flush(gb_t *);  /* internal, do not use this */

/*
 * Returns the amount of known allocated memory
 */
int statMemoryAccounted(void);

SQUIDCEXTERN unsigned int RoundTo(const unsigned int num, const unsigned int what);

#endif /* SQUID_UTIL_H */
