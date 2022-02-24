/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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

