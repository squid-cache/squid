/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_GETNAMEINFO_H
#define SQUID_COMPAT_GETNAMEINFO_H

#if !HAVE_DECL_GETNAMEINFO

// RFC 2553 / Posix resolver
// Reconstructed from KAME getnameinfo.c
SQUIDCEXTERN int xgetnameinfo(const struct sockaddr *sa,
                              socklen_t salen,
                              char *host,
                              size_t hostlen,
                              char *serv,
                              size_t servlen,
                              int flags );
#define getnameinfo xgetnameinfo

#endif /* HAVE_DECL_GETNAMEINFO */
#endif /* SQUID_COMPAT_GETNAMEINFO_H */

