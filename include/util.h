/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_UTIL_H
#define SQUID_UTIL_H

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

