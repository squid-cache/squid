/*
 * $Id: util.h,v 1.66 2003/01/17 04:53:35 robertc Exp $
 *
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

#include "config.h"
#include <stdio.h>
#include <time.h>
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if !defined(SQUIDHOSTNAMELEN)
#include <sys/param.h>
#ifndef _SQUID_NETDB_H_		/* need protection on NEXTSTEP */
#define _SQUID_NETDB_H_
#include <netdb.h>
#endif
#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 128)
#define SQUIDHOSTNAMELEN 128
#else
#define SQUIDHOSTNAMELEN MAXHOSTNAMELEN
#endif
#endif

#if defined(_SQUID_FREEBSD_)
#define _etext etext
#endif

SQUIDCEXTERN const char *getfullhostname(void);
SQUIDCEXTERN const char *mkhttpdlogtime(const time_t *);
SQUIDCEXTERN const char *mkrfc1123(time_t);
SQUIDCEXTERN char *uudecode(const char *);
SQUIDCEXTERN char *xstrdup(const char *);
SQUIDCEXTERN char *xstrndup(const char *, size_t);
SQUIDCEXTERN const char *xstrerror(void);
extern const char *xbstrerror(int);
SQUIDCEXTERN int tvSubMsec(struct timeval, struct timeval);
SQUIDCEXTERN int tvSubUsec(struct timeval, struct timeval);
SQUIDCEXTERN double tvSubDsec(struct timeval, struct timeval);
SQUIDCEXTERN char *xstrncpy(char *, const char *, size_t);
SQUIDCEXTERN size_t xcountws(const char *str);
SQUIDCEXTERN time_t parse_rfc1123(const char *str);
SQUIDCEXTERN void *xcalloc(size_t, size_t);
SQUIDCEXTERN void *xmalloc(size_t);
SQUIDCEXTERN void *xrealloc(void *, size_t);
SQUIDCEXTERN void Tolower(char *);
SQUIDCEXTERN void xfree(void *);
SQUIDCEXTERN void xxfree(const void *);
#ifdef __cplusplus
inline void *operator new(size_t size)
{
    return xmalloc(size);
}
inline void operator delete (void *address)
{
    xfree (address);
}
inline void *operator new[] (size_t size)
{
    return xmalloc(size);
}
inline void operator delete[] (void *address)
{
    xfree (address);
}
#endif

/* rfc1738.c */
SQUIDCEXTERN char *rfc1738_escape(const char *);
SQUIDCEXTERN char *rfc1738_escape_unescaped(const char *);
SQUIDCEXTERN char *rfc1738_escape_part(const char *);
SQUIDCEXTERN void rfc1738_unescape(char *);

/* html.c */
SQUIDCEXTERN char *html_quote(const char *);

#if XMALLOC_STATISTICS
SQUIDCEXTERN void malloc_statistics(void (*)(int, int, int, void *), void *);
#endif

#if XMALLOC_TRACE
#define xmalloc(size) (xmalloc_func="xmalloc",xmalloc_line=__LINE__,xmalloc_file=__FILE__,xmalloc(size))
#define xfree(ptr) (xmalloc_func="xfree",xmalloc_line=__LINE__,xmalloc_file=__FILE__,xfree(ptr))
#define xxfree(ptr) (xmalloc_func="xxfree",xmalloc_line=__LINE__,xmalloc_file=__FILE__,xxfree(ptr))
#define xrealloc(ptr,size) (xmalloc_func="xrealloc",xmalloc_line=__LINE__,xmalloc_file=__FILE__,xrealloc(ptr,size))
#define xcalloc(n,size) (xmalloc_func="xcalloc",xmalloc_line=__LINE__,xmalloc_file=__FILE__,xcalloc(n,size))
#define xstrdup(ptr) (xmalloc_func="xstrdup",xmalloc_line=__LINE__,xmalloc_file=__FILE__,xstrdup(ptr))
extern int xmalloc_line;
extern char *xmalloc_file;
extern char *xmalloc_func;
extern int xmalloc_trace;
extern size_t xmalloc_total;
extern void xmalloc_find_leaks(void);
#endif

typedef struct in_addr SIA;
SQUIDCEXTERN int safe_inet_addr(const char *, SIA *);
SQUIDCEXTERN time_t parse_iso3307_time(const char *buf);
SQUIDCEXTERN char *base64_decode(const char *coded);
SQUIDCEXTERN const char *base64_encode(const char *decoded);
SQUIDCEXTERN const char *base64_encode_bin(const char *data, int len);

SQUIDCEXTERN double xpercent(double part, double whole);
SQUIDCEXTERN int xpercentInt(double part, double whole);
SQUIDCEXTERN double xdiv(double nom, double denom);

SQUIDCEXTERN const char *xitoa(int num);

#if !HAVE_DRAND48
double drand48(void);
#endif

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

#endif /* SQUID_UTIL_H */
