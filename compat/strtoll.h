/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMPAT_STRTOLL_H
#define _SQUID_COMPAT_STRTOLL_H

#if !HAVE_STRTOLL

/**
 *\par
 * Convert a string to a int64 integer.
 *
 *\par
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
SQUIDCEXTERN int64_t strtoll(const char *nptr, char **endptr, int base);

#endif /* !HAVE_STRTOLL */
#endif /* _SQUID_COMPAT_STRTOLL_H */

