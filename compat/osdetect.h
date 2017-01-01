/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_OSDETECT_H
#define SQUID_COMPAT_OSDETECT_H

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/*
 * Define the _SQUID_TYPE_ based on a guess of the OS.
 *
 * NP: This MUST come first in compat.h with no OS-specific includes
 *     or other definitions within this if-else structure.
 */

/* SUN SOLARIS / OPENSOLARIS */
#if defined(__sun__) || defined(__sun) || defined(__SUNPRO_CC) || defined(__SunOS_OSversion)

#if defined(__SVR4) /* Solaris */
#define _SQUID_SOLARIS_ 1
#else /* SunOS */
#define _SQUID_SUNOS_ 1
#endif /* __SVR4 */

#elif defined(__hpux)       /* HP-UX - SysV-like? */
#define _SQUID_HPUX_ 1

#elif defined(__osf__)      /* OSF/1 */
#define _SQUID_OSF_ 1

#elif defined(_AIX)     /* AIX */
#define _SQUID_AIX_ 1

#elif defined(__linux__)    /* Linux. WARNING: solaris-x86 also sets this */
#define _SQUID_LINUX_ 1

#elif defined(__FreeBSD__)  /* FreeBSD */
#define _SQUID_FREEBSD_ 1

#elif defined(__FreeBSD_kernel__)      /* GNU/kFreeBSD */
#define _SQUID_KFREEBSD_ 1

#elif defined(__sgi__)  || defined(sgi) || defined(__sgi)   /* SGI */
#define _SQUID_SGI_ 1

#elif defined(__NeXT__)
#define _SQUID_NEXT_ 1

#elif defined(__NetBSD__)
#define _SQUID_NETBSD_ 1

#elif defined(__OpenBSD__)
#define _SQUID_OPENBSD_ 1

#elif defined(__DragonFly__)
#define _SQUID_DRAGONFLY_ 1

#elif defined(__CYGWIN__)
#define _SQUID_CYGWIN_ 1

#elif defined(__MINGW32__) || defined(__MINGW__)
#define _SQUID_MINGW_ 1
#define _SQUID_WINDOWS_ 1

#elif defined(WIN32) || defined(WINNT) || defined(__WIN32__) || defined(__WIN32)
#define _SQUID_WINDOWS_ 1

#elif defined(__APPLE__)
#define _SQUID_APPLE_ 1

#elif defined(sony_news) && defined(__svr4)
#define _SQUID_NEWSOS6_ 1

#elif defined(__QNX__)
#define _SQUID_QNX_ 1

#elif defined(__EMX__) || defined(OS2) || defined(__OS2__)
#define _SQUID_OS2_ 1

#endif /* OS automatic detection */

#endif /* SQUID_COMPAT_OSDETECT_H */

