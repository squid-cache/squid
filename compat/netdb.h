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

/// Provide POSIX gethostbyname(2) API on MinGW and Visual Studio build environments
struct hostent *xgethostbyname(const char * name);

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)
// Windows and MinGW implementations are in compat/netdb.cc

inline struct hostent *
xgethostbyname(const char *name)
{
    return gethostbyname(name);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
#endif /* SQUID_COMPAT_NETDB_H */
