/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_NETDB_H
#define SQUID_COMPAT_NETDB_H

#if HAVE_NETDB_H
#include <netdb.h>
#endif

/// POSIX gethostbyname(3) equivalent
struct hostent * xgethostbyname(const char * name);

/// POSIX getservbyname(3) equivalent
struct servent * xgetservbyname(const char * name, const char * proto);

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)

inline struct hostent *
xgethostbyname(const char *name)
{
    return gethostbyname(name);
}

inline struct servent *
xgetservbyname(const char *name, const char *proto)
{
    return getservbyname(name, proto);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */
#endif /* SQUID_COMPAT_NETDB_H */
