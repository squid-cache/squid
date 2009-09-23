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

#if defined(__sun__) || defined(__sun)	/* SUN */
# define _SQUID_SUN_
# if defined(__SVR4)		/* SOLARIS */
#  define _SQUID_SOLARIS_
# else /* SUNOS */
#  define _SQUID_SUNOS_
# endif

#elif defined(__hpux)		/* HP-UX - SysV-like? */
#define _SQUID_HPUX_
#define _SQUID_SYSV_

#elif defined(__osf__)		/* OSF/1 */
#define _SQUID_OSF_

#elif defined(__ultrix)		/* Ultrix */
#define _SQUID_ULTRIX_

#elif defined(_AIX)		/* AIX */
#define _SQUID_AIX_

#elif defined(__linux__)	/* Linux */
#define _SQUID_LINUX_

#elif defined(__FreeBSD__)	/* FreeBSD */
#define _SQUID_FREEBSD_

#elif defined(__FreeBSD_kernel__)      /* GNU/kFreeBSD */
#define _SQUID_KFREEBSD_

#elif defined(__sgi__)	|| defined(sgi) || defined(__sgi)	/* SGI */
#define _SQUID_SGI_

#elif defined(__NeXT__)
#define _SQUID_NEXT_

#elif defined(__bsdi__)
#define _SQUID_BSDI_		/* BSD/OS */

#elif defined(__NetBSD__)
#define _SQUID_NETBSD_

#elif defined(__OpenBSD__)
#define _SQUID_OPENBSD_

#elif defined(__DragonFly__)
#define _SQUID_DRAGONFLY_

#elif defined(__CYGWIN32__)  || defined(__CYGWIN__)
#define _SQUID_CYGWIN_
#define _SQUID_WIN32_

#elif defined(WIN32) || defined(WINNT) || defined(__WIN32__) || defined(__WIN32)
/* We are using _SQUID_MSWIN_ define in cf.data.pre, so
   it must be defined to 1 to avoid the build failure of cfgen.
 */
#define _SQUID_MSWIN_ 1
#define _SQUID_WIN32_

#elif defined(__APPLE__)
#define _SQUID_APPLE_

#elif defined(sony_news) && defined(__svr4)
#define _SQUID_NEWSOS6_

#elif defined(__QNX__)
#define _SQUID_QNX_

#elif defined(__EMX__) || defined(OS2) || defined(__OS2__)
#define _SQUID_OS2_

#endif /* OS automatic detection */



#endif /* SQUID_COMPAT_OSDETECT_H */
