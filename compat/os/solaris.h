/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_OS_SOLARIS_H
#define SQUID_COMPAT_OS_SOLARIS_H

#if _SQUID_SOLARIS_

/*
 * ugly hack. System headers require wcsstr, but don't define it.
 */
#include <wchar.h>
#ifdef wcsstr
#undef wcsstr
#endif /* wcsstr */
#define wcsstr wcswcs

/*
 * On Solaris 9 x86, gcc may includes a "fixed" set of old system
 * include files that is incompatible with the updated Solaris
 * header files.
 */
#if defined(i386) || defined(__i386)
#if !HAVE_PAD128_T
typedef union {
    long double _q;
    int32_t     _l[4];
} pad128_t;
#endif
#if !HAVE_UPAD128_T
typedef union {
    long double _q;
    uint32_t    _l[4];
} upad128_t;
#endif
#endif

/**
 * prototypes for system function missing from system includes
 * NP: sys/resource.h and sys/time.h are apparently order-dependant.
 */
#include <sys/time.h>
#include <sys/resource.h>
SQUIDCEXTERN int getrusage(int, struct rusage *);

#if defined(__SUNPRO_CC)
// Solaris 11 needs this before <sys/socket.h> to get the definition for msg_control
// and possibly other type definitions we do not know about specifically
#define _XPG4_2 1
#include <sys/socket.h>
#endif

/**
 * prototypes for system function missing from system includes
 * on some Solaris systems.
 */
SQUIDCEXTERN int getpagesize(void);
#if !defined(_XPG4_2) && !(defined(__EXTENSIONS__) || \
(!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)))
SQUIDCEXTERN int gethostname(char *, int);
#endif

/*
 * SunStudio CC does not define C++ portability API __FUNCTION__
 */
#if defined(__SUNPRO_CC) && !defined(__FUNCTION__)
#define __FUNCTION__ ""
#endif

/* Bug 2500: Solaris 10/11 require s6_addr* defines. */
//#define s6_addr8   _S6_un._S6_u8
//#define s6_addr16  _S6_un._S6_u16
#define s6_addr32  _S6_un._S6_u32

/* Bug 3057: Solaris 9 defines struct addrinfo with size_t instead of socklen_t
 *           this causes binary incompatibility on 64-bit systems.
 *  Fix this by bundling a copy of the OpenSolaris 10 netdb.h to use instead.
 */
#if defined(__sparcv9)
#include "compat/os/opensolaris_10_netdb.h"
#endif

/* Solaris 10 lacks SUN_LEN */
#if !defined(SUN_LEN)
#define SUN_LEN(su) (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

/* Soaris 10 does not define POSIX AF_LOCAL, but does define the Unix name */
#if !defined(AF_LOCAL)
#define AF_LOCAL AF_UNIX
#endif

/* Solaris lacks paths.h by default */
#if HAVE_PATHS_H
#include <paths.h>
#endif
#if !defined(_PATH_DEVNULL)
#define _PATH_DEVNULL "/dev/null"
#endif

#endif /* _SQUID_SOLARIS_ */
#endif /* SQUID_COMPAT_OS_SOLARIS_H */

