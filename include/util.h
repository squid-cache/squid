/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INCLUDE_UTIL_H
#define SQUID_INCLUDE_UTIL_H

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

SQUIDCEXTERN void Tolower(char *);

SQUIDCEXTERN double xpercent(double part, double whole);
SQUIDCEXTERN int xpercentInt(double part, double whole);
SQUIDCEXTERN double xdiv(double nom, double denom);

SQUIDCEXTERN const char *xitoa(int num);
SQUIDCEXTERN const char *xint64toa(int64_t num);

SQUIDCEXTERN const char *double_to_str(char *buf, int buf_size, double value);

#endif /* SQUID_INCLUDE_UTIL_H */

