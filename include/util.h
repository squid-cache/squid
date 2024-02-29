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

void Tolower(char *);

double xpercent(double part, double whole);
int xpercentInt(double part, double whole);
double xdiv(double nom, double denom);

const char *xitoa(int num);
const char *xint64toa(int64_t num);

const char *double_to_str(char *buf, int buf_size, double value);

#endif /* SQUID_INCLUDE_UTIL_H */

